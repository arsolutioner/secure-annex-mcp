import asyncio
import json
import os
import time
from typing import Dict, Any, Optional, List

import httpx
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.types as types
import mcp.server.stdio

# SecureAnnex API Configuration
API_BASE_URL = "https://api.secureannex.com/v0"

# Global configuration - will be populated during initialization
server_config = {}

# Initialize the MCP server
server = Server("secure-annex-mcp")

# Cache for API data with TTL
cache = {
    "extensions": {},  # {extension_id: {"data": details, "timestamp": time}}
    "versions": {},    # {extension_id: {"data": {version: details}, "timestamp": time}}
    "reviews": {},     # {extension_id: {"data": reviews, "timestamp": time}}
    "signatures": {},  # {extension_id: {"data": signatures, "timestamp": time}}
    "vulnerabilities": {},  # {extension_id: {"data": vulnerabilities, "timestamp": time}}
    "urls": {},        # {extension_id: {"data": urls, "timestamp": time}}
    "manifest": {},    # {extension_id: {"data": manifest, "timestamp": time}}
    "analysis": {},    # {extension_id: {"data": analysis, "timestamp": time}}
    "code": {},        # {extension_id: {"data": code, "timestamp": time}}
    "updates": {"data": [], "timestamp": 0},  # Recent updates
    "cache_ttl": 3600  # TTL in seconds (e.g., 1 hour)
}


def is_cache_valid(cache_key: str, item_id: Optional[str] = None) -> bool:
    """
    Check if a cached item is still valid based on TTL.
    
    Args:
        cache_key (str): The cache category to check
        item_id (Optional[str]): The specific item ID, or None for list caches
        
    Returns:
        bool: True if the cache is valid, False otherwise
    """
    current_time = time.time()
    
    # For list-type caches (like updates)
    if item_id is None:
        if cache_key not in cache or "timestamp" not in cache[cache_key]:
            return False
        return (current_time - cache[cache_key]["timestamp"]) < cache["cache_ttl"]
    
    # For dictionary-type caches
    if item_id not in cache[cache_key]:
        return False
    if "timestamp" not in cache[cache_key][item_id]:
        return False
    return (current_time - cache[cache_key][item_id]["timestamp"]) < cache["cache_ttl"]


async def fetch_from_api(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Helper function to fetch data from the SecureAnnex API.
    
    Args:
        endpoint: API endpoint to query
        params: Query parameters
        
    Returns:
        Dictionary with API response data
    """
    url = f"{API_BASE_URL}/{endpoint}"
    headers = {}
    
    # Add API key for authenticated endpoints
    if endpoint not in ["updates", "updates/rss"]:
        # Check environment variable directly as fallback
        api_key = server_config.get("api_key") or os.environ.get("SECUREANNEX_API_KEY", "")
        
        if not api_key:
            error_msg = "SecureAnnex API Key not provided in configuration or environment"
            print(f"ERROR: {error_msg}")
            print(f"server_config: {server_config}")
            print(f"SECUREANNEX_API_KEY in env: {'SECUREANNEX_API_KEY' in os.environ}")
            return {"error": error_msg}
        
        headers["x-api-key"] = api_key
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, params=params, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 429:
                error_data = response.json()
                retry_after = error_data.get("reset_at", 60)  # Default to 60 seconds
                return {
                    "error": f"API quota exceeded. Retry after {retry_after} seconds.",
                    "limit": error_data.get("limit"),
                    "reset_at": error_data.get("reset_at")
                }
                
            # Handle other errors
            if response.status_code >= 400:
                return {"error": f"API error: {response.status_code} - {response.text}"}
                
            return response.json()
        except httpx.RequestError as e:
            return {"error": f"Request error: {str(e)}"}
        except json.JSONDecodeError:
            return {"error": f"Invalid JSON response from API: {response.text}"}


@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List all available resources from SecureAnnex.
    """
    resources = []
    
    # Add extension resources
    for extension_id, details in cache["extensions"].items():
        resources.append(
            types.Resource(
                uri=AnyUrl(f"secureannex://extension/{extension_id}"),
                name=f"Extension: {details.get('data', {}).get('name', extension_id)}",
                description=f"Browser extension information for {details.get('data', {}).get('name', extension_id)}",
                mimeType="application/json",
            )
        )
    
    # Add vulnerability resources for each extension
    for extension_id, vulns in cache["vulnerabilities"].items():
        if vulns.get("data"):
            resources.append(
                types.Resource(
                    uri=AnyUrl(f"secureannex://vulnerabilities/{extension_id}"),
                    name=f"Vulnerabilities: {cache['extensions'].get(extension_id, {}).get('data', {}).get('name', extension_id)}",
                    description=f"Security vulnerabilities for extension {extension_id}",
                    mimeType="application/json",
                )
            )
    
    # Add analysis resources for each extension
    for extension_id, analysis in cache["analysis"].items():
        if analysis.get("data"):
            resources.append(
                types.Resource(
                    uri=AnyUrl(f"secureannex://analysis/{extension_id}"),
                    name=f"Analysis: {cache['extensions'].get(extension_id, {}).get('data', {}).get('name', extension_id)}",
                    description=f"AI security analysis for extension {extension_id}",
                    mimeType="application/json",
                )
            )
    
    # Add a resource for recent updates
    if cache["updates"]["data"]:
        resources.append(
            types.Resource(
                uri=AnyUrl("secureannex://updates"),
                name="Recent Updates",
                description="Recently updated browser extensions",
                mimeType="application/json",
            )
        )
    
    return resources


@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific resource's content by its URI.
    """
    if uri.scheme != "secureannex":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    path_parts = uri.path.strip("/").split("/")
    resource_type, resource_id = path_parts[0], path_parts[1] if len(path_parts) > 1 else None

    if resource_type == "extension":
        if not is_cache_valid("extensions", resource_id):
            # Fetch extension data if not in cache
            try:
                data = await fetch_from_api("extensions", {"extension_id": resource_id})
                if "result" in data and data["result"]:
                    cache["extensions"][resource_id] = {"data": data["result"][0], "timestamp": time.time()}
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)
        
        return json.dumps(cache["extensions"].get(resource_id, {}).get("data", {}), indent=2)
    
    elif resource_type == "vulnerabilities":
        if not is_cache_valid("vulnerabilities", resource_id):
            # Fetch vulnerability data if not in cache
            try:
                data = await fetch_from_api("vulnerabilities", {"extension_id": resource_id})
                if "result" in data:
                    cache["vulnerabilities"][resource_id] = {"data": data["result"], "timestamp": time.time()}
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)
        
        return json.dumps(cache["vulnerabilities"].get(resource_id, {}).get("data", []), indent=2)
    
    elif resource_type == "analysis":
        if not is_cache_valid("analysis", resource_id):
            # Fetch analysis data if not in cache
            try:
                data = await fetch_from_api("analysis", {"extension_id": resource_id})
                if "result" in data:
                    cache["analysis"][resource_id] = {"data": data["result"], "timestamp": time.time()}
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)
        
        return json.dumps(cache["analysis"].get(resource_id, {}).get("data", []), indent=2)
    
    elif resource_type == "updates":
        if not is_cache_valid("updates"):
            # Fetch updates if not in cache
            try:
                data = await fetch_from_api("updates")
                if "result" in data:
                    cache["updates"] = {"data": data["result"], "timestamp": time.time()}
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)
        
        return json.dumps(cache["updates"]["data"], indent=2)
    
    else:
        raise ValueError(f"Unknown resource type: {resource_type}")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """
    List tools to interact with the SecureAnnex API.
    """
    return [
        types.Tool(
            name="search_extensions",
            description="Search for browser extensions based on various criteria.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by extension name"},
                    "extension_id": {"type": "string", "description": "Filter by extension ID"},
                    "owner": {"type": "string", "description": "Filter by extension owner"},
                    "featured": {"type": "boolean", "description": "Filter by featured status"},
                    "active": {"type": "boolean", "description": "Filter by active status"},
                    "page": {"type": "integer", "description": "Page number (default: 1)"},
                    "page_size": {"type": "integer", "description": "Results per page (default: 10, max: 25)"}
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_extension_details",
            description="Get detailed information about a specific extension by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension to fetch"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_versions",
            description="Get version history for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_reviews",
            description="Get user reviews for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "rating": {"type": "integer", "description": "Filter by rating (1-5)"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_vulnerabilities",
            description="Get security vulnerabilities for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_signatures",
            description="Get security signatures for extensions, filterable by rule, name, or extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"},
                    "rule": {"type": "string", "description": "Filter by signature rule"},
                    "name": {"type": "string", "description": "Filter by name"},
                    "limit": {"type": "integer", "description": "Optional: Maximum number of results to return (default: all)"}
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_extension_urls",
            description="Get network URLs used by a specific extension or by domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"},
                    "domain": {"type": "string", "description": "Filter by domain"},
                    "url": {"type": "string", "description": "Filter by URL"},
                    "limit": {"type": "integer", "description": "Optional: Maximum number of results to return (default: all)"}
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_extension_manifest_risks",
            description="Get manifest permission risks for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"},
                    "risk_type": {"type": "string", "description": "Filter by risk type"},
                    "risk_id": {"type": "string", "description": "Filter by risk ID"},
                    "limit": {"type": "integer", "description": "Optional: Maximum number of results to return (default: all)"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_analysis",
            description="Get AI security analysis for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_extension_code_review",
            description="Get code security review for a specific extension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "extension_id": {"type": "string", "description": "The ID of the extension"},
                    "version": {"type": "string", "description": "Filter by specific version"}
                },
                "required": ["extension_id"],
            },
        ),
        types.Tool(
            name="get_recent_updates",
            description="Get recently updated extensions.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> list[types.TextContent]:
    """
    Handle tool execution requests for interacting with the SecureAnnex API.
    """
    if arguments is None:
        arguments = {}
    
    try:
        if name == "search_extensions":
            # Prepare parameters for API call
            params = {k: v for k, v in arguments.items() if k in [
                "name", "extension_id", "owner", "featured", "active", "page", "page_size"
            ]}
            
            # Default to 10 items per page
            if "page_size" not in params:
                params["page_size"] = 10
            
            data = await fetch_from_api("extensions", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            for extension in data.get("result", []):
                if "extension_id" in extension:
                    cache["extensions"][extension["extension_id"]] = {"data": extension, "timestamp": time.time()}
            
            # Format the response
            extension_list = "\n\n".join([
                f"ID: {ext.get('extension_id', 'N/A')}\n"
                f"Name: {ext.get('name', 'N/A')}\n"
                f"Owner: {ext.get('owner', 'N/A')}\n"
                f"Rating: {ext.get('rating', 'N/A')} ({ext.get('num_ratings', 0)} ratings)\n"
                f"Users: {ext.get('users', 'N/A')}\n"
                f"Latest Version: {ext.get('latest', 'N/A')}\n"
                f"Overview: {ext.get('overview', 'N/A')}"
                for ext in data.get("result", [])
            ])
            
            pagination_info = (
                f"Page {data.get('page', 1)} of {data.get('total_pages', 1)} "
                f"(Total extensions: {data.get('total_count', 0)})"
            )
            
            return [types.TextContent(
                type="text",
                text=f"Extensions matching your search criteria:\n\n{extension_list}\n\n{pagination_info}"
            )]

        elif name == "get_extension_details":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            data = await fetch_from_api("extensions", {"extension_id": extension_id})
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            if not data.get("result"):
                return [types.TextContent(type="text", text=f"No extension found with ID: {extension_id}")]
            
            # Cache the result
            extension = data["result"][0]
            cache["extensions"][extension_id] = {"data": extension, "timestamp": time.time()}
            
            return [types.TextContent(type="text", text=json.dumps(extension, indent=2))]

        elif name == "get_extension_versions":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            params = {"extension_id": extension_id}
            if "version" in arguments:
                params["version"] = arguments["version"]
            
            data = await fetch_from_api("versions", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["versions"][extension_id] = {"data": {version["version"]: version for version in data.get("result", [])}, "timestamp": time.time()}
            
            versions_text = "\n\n".join([
                f"Version: {version.get('version', 'N/A')}\n"
                f"Name: {version.get('name', 'N/A')}\n"
                f"Updated: {version.get('updated_date', 'N/A')}\n"
                f"Manifest Version: {version.get('manifest_version', 'N/A')}"
                for version in data.get("result", [])
            ])
            
            return [types.TextContent(
                type="text",
                text=f"Versions for extension {extension_id}:\n\n{versions_text}"
            )]

        elif name == "get_extension_reviews":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            params = {"extension_id": extension_id}
            if "rating" in arguments:
                params["rating"] = arguments["rating"]
            
            data = await fetch_from_api("reviews", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["reviews"][extension_id] = {"data": data.get("result", []), "timestamp": time.time()}
            
            if not data.get("result"):
                return [types.TextContent(
                    type="text",
                    text=f"No reviews found for extension {extension_id}"
                )]
            
            reviews_text = "\n\n".join([
                f"User: {review.get('user', 'Anonymous')}\n"
                f"Rating: {review.get('rating', 'N/A')}\n"
                f"Date: {review.get('date', 'N/A')}\n"
                f"Review: {review.get('review', 'No content')}"
                for review in data.get("result", [])
            ])
            
            return [types.TextContent(
                type="text",
                text=f"Reviews for extension {extension_id}:\n\n{reviews_text}"
            )]

        elif name == "get_extension_vulnerabilities":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            params = {"extension_id": extension_id}
            if "version" in arguments:
                params["version"] = arguments["version"]
            
            data = await fetch_from_api("vulnerabilities", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["vulnerabilities"][extension_id] = {"data": data.get("result", []), "timestamp": time.time()}
            
            if not data.get("result"):
                return [types.TextContent(
                    type="text",
                    text=f"No vulnerabilities found for extension {extension_id}"
                )]
            
            # Format the vulnerabilities in a readable way
            vulns_text = "\n\n".join([
                f"Component: {vuln.get('component', 'N/A')}\n"
                f"Version: {vuln.get('version', 'N/A')}\n"
                f"Severity: {vuln.get('vulnerability', {}).get('severity', 'N/A')}\n"
                f"Summary: {vuln.get('vulnerability', {}).get('identifiers', {}).get('summary', 'N/A')}\n"
                f"CVEs: {', '.join(vuln.get('vulnerability', {}).get('identifiers', {}).get('CVE', ['None']))}"
                for vuln in data.get("result", [])
            ])
            
            return [types.TextContent(
                type="text",
                text=f"Vulnerabilities for extension {extension_id}:\n\n{vulns_text}"
            )]

        elif name == "get_extension_signatures":
            params = {}
            limit = arguments.get("limit")  # Optional max results
            
            # Add all valid parameters to the query
            for param in ["extension_id", "version", "rule", "name"]:
                if param in arguments and arguments[param]:
                    params[param] = arguments[param]
            
            # Validate that at least one search parameter is provided
            if not any(k in params for k in ["extension_id", "rule", "name"]):
                return [types.TextContent(
                    type="text", 
                    text="Error: At least one of extension_id, rule, or name is required"
                )]
            
            # Set maximum page size to reduce API calls
            params["page_size"] = 100  # Maximum allowed
            
            # First, get just page 1 and check total
            data = await fetch_from_api("signatures", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            all_results = data.get("result", [])
            total_count = data.get("total_count", 0)
            total_pages = data.get("total_pages", 1)
            
            # Early return if we have all results or hit the limit
            if total_pages <= 1 or (limit and len(all_results) >= limit):
                if limit and len(all_results) > limit:
                    all_results = all_results[:limit]  # Respect the limit
            else:
                # Calculate how many more pages we need
                if limit:
                    # If we have a limit, only fetch enough pages to reach it
                    items_needed = max(0, limit - len(all_results))
                    # Calculate how many more pages needed to reach limit
                    pages_needed = min(total_pages - 1, (items_needed + params["page_size"] - 1) // params["page_size"])
                else:
                    # No limit, fetch all remaining pages
                    pages_needed = total_pages - 1
                
                # Only fetch more pages if needed
                if pages_needed > 0:
                    # Fetch remaining pages in parallel to reduce time
                    async def fetch_page(page_num):
                        page_params = params.copy()
                        page_params["page"] = page_num
                        return await fetch_from_api("signatures", page_params)
                    
                    # Create tasks for remaining pages
                    tasks = [fetch_page(i+2) for i in range(pages_needed)]
                    page_results = await asyncio.gather(*tasks)
                    
                    # Process results from all pages
                    for page_data in page_results:
                        if not "error" in page_data and page_data.get("result"):
                            all_results.extend(page_data["result"])
                            
                            # Break early if we've reached our limit
                            if limit and len(all_results) >= limit:
                                break
                    
                    # Respect the limit if specified
                    if limit and len(all_results) > limit:
                        all_results = all_results[:limit]
            
            # Cache the results (only for specific extension_id queries)
            if "extension_id" in params:
                cache["signatures"][params["extension_id"]] = {"data": all_results, "timestamp": time.time()}
            
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"No signatures found"
                )]
            
            # Format the signatures in a readable way
            sigs_text = "\n\n".join([
                f"Rule: {sig.get('rule', 'N/A')}\n"
                f"Severity: {sig.get('meta', {}).get('severity', 'N/A')}\n"
                f"Description: {sig.get('meta', {}).get('description', 'N/A')}\n"
                f"File: {sig.get('file_path', 'N/A')}\n"
                f"Extension ID: {sig.get('extension_id', 'N/A')}\n"
                f"Version: {sig.get('version', 'N/A')}"
                for sig in all_results
            ])
            
            # Include limiting info in result if applicable
            result_count_text = f"Total found: {total_count}" if not limit or len(all_results) == total_count else f"Showing {len(all_results)} of {total_count} total"
            
            return [types.TextContent(
                type="text",
                text=f"Security signatures ({result_count_text}):\n\n{sigs_text}"
            )]

        elif name == "get_extension_manifest_risks":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            params = {"extension_id": extension_id}
            limit = arguments.get("limit")  # Optional max results
            
            # Add optional parameters
            for param in ["version", "risk_type", "risk_id"]:
                if param in arguments and arguments[param]:
                    params[param] = arguments[param]
            
            # Set maximum page size to reduce API calls
            params["page_size"] = 100  # Maximum allowed
            
            # First, get just page 1 and check total
            data = await fetch_from_api("manifest", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            all_results = data.get("result", [])
            total_count = data.get("total_count", 0)
            total_pages = data.get("total_pages", 1)
            
            # Early return if we have all results or hit the limit
            if total_pages <= 1 or (limit and len(all_results) >= limit):
                if limit and len(all_results) > limit:
                    all_results = all_results[:limit]  # Respect the limit
            else:
                # Calculate how many more pages we need
                if limit:
                    # If we have a limit, only fetch enough pages to reach it
                    items_needed = max(0, limit - len(all_results))
                    # Calculate how many more pages needed to reach limit
                    pages_needed = min(total_pages - 1, (items_needed + params["page_size"] - 1) // params["page_size"])
                else:
                    # No limit, fetch all remaining pages
                    pages_needed = total_pages - 1
                
                # Only fetch more pages if needed
                if pages_needed > 0:
                    # Fetch remaining pages in parallel to reduce time
                    async def fetch_page(page_num):
                        page_params = params.copy()
                        page_params["page"] = page_num
                        return await fetch_from_api("manifest", page_params)
                    
                    # Create tasks for remaining pages
                    tasks = [fetch_page(i+2) for i in range(pages_needed)]
                    page_results = await asyncio.gather(*tasks)
                    
                    # Process results from all pages
                    for page_data in page_results:
                        if not "error" in page_data and page_data.get("result"):
                            all_results.extend(page_data["result"])
                            
                            # Break early if we've reached our limit
                            if limit and len(all_results) >= limit:
                                break
                    
                    # Respect the limit if specified
                    if limit and len(all_results) > limit:
                        all_results = all_results[:limit]
            
            # Cache the results
            cache["manifest"][extension_id] = {"data": all_results, "timestamp": time.time()}
            
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"No manifest risks found for extension {extension_id}"
                )]
            
            # Format the manifest risks in a readable way
            risks_text = "\n\n".join([
                f"Risk Type: {risk.get('risk_type', 'N/A')}\n"
                f"Risk ID: {risk.get('risk_id', 'N/A')}\n"
                f"Severity: {risk.get('severity', 'N/A')}/10\n"
                f"Description: {risk.get('description', 'N/A')}\n"
                f"Snippet: {risk.get('snippet', 'N/A')}"
                for risk in all_results
            ])
            
            # Include limiting info in result if applicable
            result_count_text = f"Total found: {total_count}" if not limit or len(all_results) == total_count else f"Showing {len(all_results)} of {total_count} total"
            
            return [types.TextContent(
                type="text",
                text=f"Manifest risks for extension {extension_id} ({result_count_text}):\n\n{risks_text}"
            )]

        elif name == "get_extension_urls":
            params = {}
            limit = arguments.get("limit")  # Optional max results
            
            # Add all valid parameters to the query
            for param in ["extension_id", "version", "domain", "url"]:
                if param in arguments and arguments[param]:
                    params[param] = arguments[param]
            
            # Validate that at least one search parameter is provided
            if not any(k in params for k in ["extension_id", "domain", "url"]):
                return [types.TextContent(
                    type="text", 
                    text="Error: At least one of extension_id, domain, or url is required"
                )]
            
            # Set maximum page size to reduce API calls
            params["page_size"] = 100  # Maximum allowed
            
            # First, get just page 1 and check total
            data = await fetch_from_api("urls", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            all_results = data.get("result", [])
            total_count = data.get("total_count", 0)
            total_pages = data.get("total_pages", 1)
            
            # Early return if we have all results or hit the limit
            if total_pages <= 1 or (limit and len(all_results) >= limit):
                if limit and len(all_results) > limit:
                    all_results = all_results[:limit]  # Respect the limit
            else:
                # Calculate how many more pages we need
                if limit:
                    # If we have a limit, only fetch enough pages to reach it
                    items_needed = max(0, limit - len(all_results))
                    # Calculate how many more pages needed to reach limit
                    pages_needed = min(total_pages - 1, (items_needed + params["page_size"] - 1) // params["page_size"])
                else:
                    # No limit, fetch all remaining pages
                    pages_needed = total_pages - 1
                
                # Only fetch more pages if needed
                if pages_needed > 0:
                    # Fetch remaining pages in parallel to reduce time
                    async def fetch_page(page_num):
                        page_params = params.copy()
                        page_params["page"] = page_num
                        return await fetch_from_api("urls", page_params)
                    
                    # Create tasks for remaining pages
                    tasks = [fetch_page(i+2) for i in range(pages_needed)]
                    page_results = await asyncio.gather(*tasks)
                    
                    # Process results from all pages
                    for page_data in page_results:
                        if not "error" in page_data and page_data.get("result"):
                            all_results.extend(page_data["result"])
                            
                            # Break early if we've reached our limit
                            if limit and len(all_results) >= limit:
                                break
                    
                    # Respect the limit if specified
                    if limit and len(all_results) > limit:
                        all_results = all_results[:limit]
            
            # Cache the results (only for specific extension_id queries)
            if "extension_id" in params:
                cache["urls"][params["extension_id"]] = {"data": all_results, "timestamp": time.time()}
            
            if not all_results:
                return [types.TextContent(
                    type="text",
                    text=f"No URLs found"
                )]
            
            # Format the URLs in a readable way
            urls_text = "\n\n".join([
                f"URL: {url.get('url', 'N/A')}\n"
                f"Domain: {url.get('domain', 'N/A')}\n"
                f"File: {url.get('file_path', 'N/A')}\n"
                f"Version: {url.get('version', 'N/A')}"
                for url in all_results
            ])
            
            # Include limiting info in result if applicable
            result_count_text = f"Total found: {total_count}" if not limit or len(all_results) == total_count else f"Showing {len(all_results)} of {total_count} total"
            
            return [types.TextContent(
                type="text",
                text=f"URLs ({result_count_text}):\n\n{urls_text}"
            )]

        elif name == "get_extension_analysis":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            data = await fetch_from_api("analysis", {"extension_id": extension_id})
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["analysis"][extension_id] = {"data": data.get("result", []), "timestamp": time.time()}
            
            if not data.get("result"):
                return [types.TextContent(
                    type="text",
                    text=f"No AI analysis found for extension {extension_id}"
                )]
            
            # Return the first analysis
            analysis = data["result"][0]
            
            return [types.TextContent(
                type="text",
                text=f"AI Analysis for extension {extension_id} (version {analysis.get('version', 'N/A')}):\n\n"
                     f"{analysis.get('analysis', 'No analysis available')}"
            )]

        elif name == "get_extension_code_review":
            extension_id = arguments.get("extension_id")
            if not extension_id:
                return [types.TextContent(type="text", text="Error: extension_id is required")]
            
            params = {"extension_id": extension_id}
            if "version" in arguments:
                params["version"] = arguments["version"]
            
            data = await fetch_from_api("code", params)
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["code"][extension_id] = {"data": data.get("result", []), "timestamp": time.time()}
            
            if not data.get("result"):
                return [types.TextContent(
                    type="text",
                    text=f"No code review found for extension {extension_id}"
                )]
            
            # Return the first code review
            code_review = data["result"][0]
            
            return [types.TextContent(
                type="text",
                text=f"Code Review for extension {extension_id} (version {code_review.get('version', 'N/A')}):\n\n"
                     f"{code_review.get('analysis', 'No code review available')}"
            )]

        elif name == "get_recent_updates":
            data = await fetch_from_api("updates")
            
            if "error" in data:
                return [types.TextContent(type="text", text=f"Error: {data['error']}")]
            
            # Cache the results
            cache["updates"] = {"data": data.get("result", []), "timestamp": time.time()}
            
            if not data.get("result"):
                return [types.TextContent(
                    type="text",
                    text="No recent updates found"
                )]
            
            # Format the updates in a readable way
            updates_text = "\n\n".join([
                f"Name: {update.get('name', 'N/A')}\n"
                f"Extension ID: {update.get('extension_id', 'N/A')}\n"
                f"Version: {update.get('version', 'N/A')}\n"
                f"Date: {update.get('date', 'N/A')}\n"
                f"Owner: {update.get('owner', 'N/A')}"
                for update in data.get("result", [])
            ])
            
            return [types.TextContent(
                type="text",
                text=f"Recent extension updates:\n\n{updates_text}"
            )]

        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error executing tool: {str(e)}")]


async def main():
    """Start the MCP server."""
    global server_config
    
    async def on_initialize(config):
        """Handle server initialization and extract config values."""
        global server_config
        
        # First check environment variable, then fall back to config
        env_api_key = os.environ.get("SECUREANNEX_API_KEY", "")
        if env_api_key:
            server_config["api_key"] = env_api_key
        elif "api_key" in config:
            server_config["api_key"] = config["api_key"]
                
        # Return success if we have an API key
        if server_config.get("api_key"):
            return {"status": "success"}
        else:
            return {
                "status": "error", 
                "message": "SecureAnnex API Key not provided in configuration or environment"
            }
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="secure-annex",
                server_version="0.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={
                        "configuration": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "api_key": {
                                        "type": "string",
                                        "description": "SecureAnnex API Key"
                                    }
                                },
                                "required": ["api_key"]
                            }
                        }
                    },
                ),
                on_initialize=on_initialize
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())

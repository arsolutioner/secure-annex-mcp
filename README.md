![MIT License](https://img.shields.io/badge/license-MIT-green)

<p align="center">
  <img src="https://github.com/user-attachments/assets/49f79b69-d9c0-4dca-b707-cb28c05289ae" alt="Centered Image" width="500">
</p>
<hr />

# SecureAnnex MCP Server
A Model Context Protocol (MCP) server for analyzing browser extension security. This server provides tools for querying, analyzing, and evaluating security aspects of browser extensions including vulnerability detection, signature checking, code review, and more.



## Quick Setup

No manual Python environment setup is needed. This MCP server is designed to work with Claude Desktop, which automatically handles all dependencies using the `uv` package manager and the included `pyproject.toml` file.

To get started:

1. Download or clone this repository
2. Make sure the `pyproject.toml` file is in the project directory
3. Configure Claude Desktop as shown below
4. Optional: If Claude can't find the `uv` command, use the absolute path instead, You can find the absolute path by running `which uv` in your terminal.



## Claude Desktop Configuration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secureannex": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/secure-annex-mcp",
        "run",
        "secure_annex_mcp"
      ],
      "env": {
        "SECUREANNEX_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

**Note**: Replace `/path/to/secure-annex-mcp` with the absolute path to your SecureAnnex MCP server directory.

## Project Structure

```
secure-annex-mcp/
├── pyproject.toml         # Package configuration
├── README.md              # Project documentation
└── secure_annex_mcp/      # Main package
    ├── __init__.py        # Package initialization
    ├── __main__.py        # Entry point when run as a module
    └── server.py          # MCP server implementation
```

## Available Tools

### Extension Search and Information

- **search_extensions**: Search for browser extensions based on various criteria
  - Parameters: name, extension_id, owner, featured, active, page, page_size

- **get_extension_details**: Get detailed information about a specific extension
  - Parameters: extension_id (required)

- **get_extension_versions**: Get version history for a specific extension
  - Parameters: extension_id (required), version

### Security Analysis

- **get_extension_vulnerabilities**: Get security vulnerabilities for a specific extension
  - Parameters: extension_id (required), version

- **get_extension_signatures**: Get security signatures for a specific extension
  - Parameters: extension_id (required), version, rule

- **get_extension_urls**: Get network URLs used by a specific extension
  - Parameters: extension_id (required), version, domain

- **get_extension_manifest_risks**: Get manifest permission risks for a specific extension
  - Parameters: extension_id (required), version, risk_type

- **get_extension_analysis**: Get AI security analysis for a specific extension
  - Parameters: extension_id (required)

- **get_extension_code_review**: Get code security review for a specific extension
  - Parameters: extension_id (required), version

### User Feedback

- **get_extension_reviews**: Get user reviews for a specific extension
  - Parameters: extension_id (required), rating

### Updates

- **get_recent_updates**: Get recently updated extensions
  - Parameters: None

## Example Usage

Here are some practical examples of how to use the tools with Claude:

### Searching for Extensions

```
# Get all extensions developed by specific developer
I need to find all extensions by help@getadblock.com

# Claude would use:
{
  "name": "search_extensions",
  "arguments": {
    "owner": "help@getadblock.com"
  }
}
```

### Security Analysis

```
# Get all security signatures for an extension
Show me all security signatures for the AdBlock extension

# Claude would use:
{
  "name": "get_extension_signatures",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}

# Extract all network domains from an extension
Extract all domains embedded in the AdBlock extension

# Claude would use:
{
  "name": "get_extension_urls",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}

# Analyze manifest permissions
Show me a table of all permissions requested by AdBlock with explanations

# Claude would use:
{
  "name": "get_extension_manifest_risks",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}
```

### Integration with Other MCPs

```
# Leveraging VirusTotal MCP for domain reputation
Can you extract all domains from the AdBlock extension and check their reputation on VirusTotal?

# Claude would use both SecureAnnex and VirusTotal MCPs:
# 1. First, get domains from SecureAnnex
{
  "name": "get_extension_urls",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}

# 2. Then for each domain, check VirusTotal
{
  "name": "domain_report",  // VirusTotal MCP tool
  "arguments": {
    "domain": "example.com"  // For each domain found
  }
}

# 3. Claude would compile results into a table:
| Domain | Reputation | Detection Ratio | Categories |
|--------|------------|-----------------|------------|
| domain1.com | Clean | 0/85 | Advertising |
| domain2.com | Suspicious | 3/85 | Marketing |
```

### Comprehensive Analysis

```
# Request a complete security review of an extension
Perform a full security audit of the AdBlock extension

# Claude would combine multiple tools:
{
  "name": "get_extension_details",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}

{
  "name": "get_extension_vulnerabilities",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}

{
  "name": "get_extension_analysis",
  "arguments": {
    "extension_id": "gighmmpiobklfepjocnamgkkbiglidom"
  }
}
```

## API Key

The SecureAnnex MCP server requires an API key for authentication with the SecureAnnex API. Obtain your API key from the SecureAnnex service and include it in the Claude Desktop configuration as shown above.

## Troubleshooting

If you encounter any issues:

1. Ensure your API key is correctly set in the environment variables
2. Verify the path in your Claude Desktop configuration is correct
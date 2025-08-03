
# Exabeam MCP Server

A Model Context Protocol (MCP) server that enables Claude Desktop to interact with Exabeam SIEM for security analysis and threat investigation.

## Features

- **Search Events**: Query security events with flexible search parameters
- **User Timeline**: Get activity timeline for specific users
- **Notable Events**: Retrieve high-risk and notable security events
- **Risk Scoring**: Check user risk scores and risk factors
- **Asset Search**: Search for devices and assets in your environment

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   npm install
   ```

## Configuration

### Claude Desktop Integration

1. Locate your Claude Desktop configuration file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the Exabeam MCP server configuration:
   ```json
   {
     "mcpServers": {
       "exabeam": {
         "command": "node",
         "args": ["/absolute/path/to/exabeam-mcp-server.js"],
         "env": {
           "EXABEAM_URL": "https://your-exabeam-instance.com",
           "EXABEAM_API_KEY": "your_api_key_here",
           "EXABEAM_API_SECRET": "your_api_secret_here"
         }
       }
     }
   }
   ```

3. Restart Claude Desktop

## Usage Examples

Once configured, you can ask Claude to:

- "Search for failed login attempts in the last 24 hours"
- "Show me the timeline for user john.doe"
- "What are the critical security events from today?"
- "Check the risk score for user jane.smith"
- "Find all servers with hostname containing 'web'"

## Available Tools

### search_events
Search for security events with filters:
- `query`: Search query string
- `startTime`: ISO format start time
- `endTime`: ISO format end time
- `limit`: Maximum results

### get_user_timeline
Get user activity timeline:
- `username`: Target username
- `days`: Number of days to look back

### get_notable_events
Retrieve high-risk events:
- `severity`: Minimum severity (low/medium/high/critical)
- `hours`: Look back period in hours

### get_user_risk_score
Check user risk score:
- `username`: Target username

### search_assets
Search for assets/devices:
- `query`: Search query
- `assetType`: Filter by type (server/workstation/network_device/all)

## API Notes

This implementation assumes Exabeam's REST API v2. You may need to adjust the endpoints based on your Exabeam version:

- Exabeam Cloud: Uses the endpoints as shown
- Exabeam On-Premise: May have different API paths
- Legacy versions: Might require different authentication methods

## Troubleshooting

1. **Authentication Errors**: Verify your credentials and Exabeam URL
2. **Connection Issues**: Check network connectivity and firewall rules
3. **API Errors**: Ensure your Exabeam user has appropriate API permissions
4. **Tool Not Found**: Restart Claude Desktop after configuration changes


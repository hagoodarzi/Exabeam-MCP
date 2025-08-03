// exabeam-mcp-server.js
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';

class ExabeamMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'exabeam-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.exabeamConfig = {
      baseUrl: process.env.EXABEAM_URL,
      apiKey: process.env.EXABEAM_API_KEY,
      apiSecret: process.env.EXABEAM_API_SECRET,
    };

    // Validate required configuration
    if (!this.exabeamConfig.baseUrl) {
      throw new Error('EXABEAM_URL environment variable is required');
    }
    if (!this.exabeamConfig.apiKey || !this.exabeamConfig.apiSecret) {
      throw new Error('Both EXABEAM_API_KEY and EXABEAM_API_SECRET environment variables are required');
    }

    this.setupHandlers();
  }

  async authenticate() {
    try {
      // Always use us-west endpoint for authentication as it works globally
      const authUrl = 'https://api.us-west.exabeam.cloud/auth/v1/token';
      
      // OAuth 2.0 Client Credentials flow - matching the working curl command
      const response = await axios.post(
        authUrl,
        {
          grant_type: 'client_credentials',
          client_id: this.exabeamConfig.apiKey,
          client_secret: this.exabeamConfig.apiSecret,
        },
        {
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          }
        }
      );
      
      // Return the access token
      return response.data.access_token;
    } catch (error) {
      console.error('Authentication error:', error.response?.data || error.message);
      throw new Error(`Authentication failed: ${error.response?.data?.error_description || error.message}`);
    }
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'search_events',
          description: 'Search for security events in Exabeam SIEM',
          inputSchema: {
            type: 'object',
            properties: {
              query: {
                type: 'string',
                description: 'Search query (e.g., "user:john.doe AND action:login")',
              },
              startTime: {
                type: 'string',
                description: 'Start time in ISO format (e.g., "2024-01-01T00:00:00Z")',
              },
              endTime: {
                type: 'string',
                description: 'End time in ISO format (e.g., "2024-01-02T00:00:00Z")',
              },
              limit: {
                type: 'number',
                description: 'Maximum number of results (default: 100)',
                default: 100,
              },
            },
            required: ['query'],
          },
        },
        {
          name: 'get_user_timeline',
          description: 'Get timeline of activities for a specific user',
          inputSchema: {
            type: 'object',
            properties: {
              username: {
                type: 'string',
                description: 'Username to investigate',
              },
              days: {
                type: 'number',
                description: 'Number of days to look back (default: 7)',
                default: 7,
              },
            },
            required: ['username'],
          },
        },
        {
          name: 'get_notable_events',
          description: 'Retrieve notable/high-risk events',
          inputSchema: {
            type: 'object',
            properties: {
              severity: {
                type: 'string',
                description: 'Minimum severity level (low, medium, high, critical)',
                enum: ['low', 'medium', 'high', 'critical'],
                default: 'medium',
              },
              hours: {
                type: 'number',
                description: 'Look back period in hours (default: 24)',
                default: 24,
              },
            },
          },
        },
        {
          name: 'get_user_risk_score',
          description: 'Get risk score and risk factors for a user',
          inputSchema: {
            type: 'object',
            properties: {
              username: {
                type: 'string',
                description: 'Username to check risk score',
              },
            },
            required: ['username'],
          },
        },
        {
          name: 'search_assets',
          description: 'Search for assets/devices in Exabeam',
          inputSchema: {
            type: 'object',
            properties: {
              query: {
                type: 'string',
                description: 'Asset search query (hostname, IP, etc.)',
              },
              assetType: {
                type: 'string',
                description: 'Type of asset (server, workstation, network_device)',
                enum: ['server', 'workstation', 'network_device', 'all'],
                default: 'all',
              },
            },
            required: ['query'],
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const token = await this.authenticate();
        const headers = {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        };

        switch (name) {
          case 'search_events':
            return await this.searchEvents(args, headers);
          
          case 'get_user_timeline':
            return await this.getUserTimeline(args, headers);
          
          case 'get_notable_events':
            return await this.getNotableEvents(args, headers);
          
          case 'get_user_risk_score':
            return await this.getUserRiskScore(args, headers);
          
          case 'search_assets':
            return await this.searchAssets(args, headers);
          
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
        };
      }
    });
  }

  async searchEvents(args, headers) {
    const { query, startTime, endTime, limit = 100 } = args;
    
    // Use EU endpoint as indicated by the token audience
    const apiBaseUrl = 'https://api.eu.exabeam.cloud';
    
    // Build the search query according to the API documentation
    const searchParams = {
      filter: query || '',  // Empty string instead of wildcard
      fields: ['time', 'user', 'action', 'result', 'src_ip', 'dest_ip'],  // Basic fields
      startTime: startTime || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      endTime: endTime || new Date().toISOString(),
      limit: limit
    };

    try {
      const response = await axios.post(
        `${apiBaseUrl}/search/v2/events`,
        searchParams,
        { 
          headers: {
            ...headers,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          }
        }
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response.data, null, 2),
          },
        ],
      };
    } catch (error) {
      const errorDetails = {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        request: searchParams
      };
      console.error('Search error details:', JSON.stringify(errorDetails, null, 2));
      
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error.response?.status} - ${error.response?.statusText}\n\nDetails: ${JSON.stringify(error.response?.data || error.message, null, 2)}\n\nRequest sent: ${JSON.stringify(searchParams, null, 2)}`,
          },
        ],
      };
    }
  }

  async getUserTimeline(args, headers) {
    const { username, days = 7 } = args;
    
    // Use EU endpoint
    const apiBaseUrl = 'https://api.eu.exabeam.cloud';
    
    const endTime = new Date();
    const startTime = new Date();
    startTime.setDate(startTime.getDate() - days);

    const response = await axios.get(
      `${apiBaseUrl}/users/v1/${username}/timeline`,
      {
        params: {
          startTime: startTime.toISOString(),
          endTime: endTime.toISOString(),
        },
        headers,
      }
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response.data, null, 2),
        },
      ],
    };
  }

  async getNotableEvents(args, headers) {
    const { severity = 'medium', hours = 24 } = args;
    
    // Use EU endpoint
    const apiBaseUrl = 'https://api.eu.exabeam.cloud';
    
    const endTime = new Date();
    const startTime = new Date();
    startTime.setHours(startTime.getHours() - hours);

    const severityMap = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };

    const response = await axios.get(
      `${apiBaseUrl}/notable-events/v1/events`,
      {
        params: {
          minSeverity: severityMap[severity],
          startTime: startTime.toISOString(),
          endTime: endTime.toISOString(),
        },
        headers,
      }
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response.data, null, 2),
        },
      ],
    };
  }

  async getUserRiskScore(args, headers) {
    const { username } = args;
    
    // Use EU endpoint
    const apiBaseUrl = 'https://api.eu.exabeam.cloud';

    const response = await axios.get(
      `${apiBaseUrl}/users/v1/${username}/risk-score`,
      { headers }
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response.data, null, 2),
        },
      ],
    };
  }

  async searchAssets(args, headers) {
    const { query, assetType = 'all' } = args;
    
    // Use EU endpoint
    const apiBaseUrl = 'https://api.eu.exabeam.cloud';

    const searchParams = {
      query,
      limit: 50,
    };

    if (assetType !== 'all') {
      searchParams.assetType = assetType;
    }

    const response = await axios.post(
      `${apiBaseUrl}/assets/v1/search`,
      searchParams,
      { headers }
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response.data, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Exabeam MCP server running on stdio');
  }
}

// Run the server
const server = new ExabeamMCPServer();
server.run().catch(console.error);
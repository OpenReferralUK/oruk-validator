# Open Referral UK API

Open Referral UK (ORUK) is an open data standard that provides a consistent way to publish and describe information. This makes it easier for people to find what they need and supports connected local services.

For more information about the Open Referral UK project please check out [openreferraluk.org](https://openreferraluk.org/)

## Overview

### Purpose

This solution provides a comprehensive validation service for Open Referral UK (ORUK) API implementations. It enables organizations to:

- **Validate OpenAPI Specifications**: Verify OpenAPI/Swagger specifications comply with ORUK and HSDS-UK standards
- **Test Live Endpoints**: Execute automated tests against live API endpoints to verify functionality
- **Schema Compliance**: Validate API responses against HSDS-UK (Human Services Data Specification UK) JSON schemas
- **Quality Analysis**: Assess API documentation quality, security configuration, and best practices adherence
- **Performance Metrics**: Measure endpoint response times and performance characteristics
- **Ensure Interoperability**: Help organizations build consistent, standards-compliant service directory APIs

### Key Features

- **OpenAPI Validation**: Validates OpenAPI 2.0 (Swagger) and 3.x specifications for structural correctness
- **Multi-version Schema Support**: Supports HSDS-UK v1.0 and v3.0 standards
- **Automated Endpoint Testing**: Tests all endpoints defined in OpenAPI specs against live APIs
- **Comprehensive Analysis**: Provides quality metrics, security analysis, and actionable recommendations
- **Optional Endpoint Support**: Intelligently handles optional endpoints with configurable warning levels
- **Mock Data Service**: Built-in mock endpoints for testing validation logic
- **RESTful API**: Clean, well-documented API with OpenAPI/Swagger documentation
- **Scheduled Feed Validation**: Background service for automated periodic validation of registered feeds
- **Rate Limiting**: Configurable rate limiting to protect against excessive requests
- **Health Checks**: Kubernetes-ready liveness and readiness probes
- **OpenTelemetry Integration**: Distributed tracing and metrics for observability

## Technical Architecture

This solution is built as a modern, cloud-native application with the following components:

### Backend (ASP.NET Core API)

- **Framework**: .NET 10.0 with ASP.NET Core
- **Language**: C# 13+ with nullable reference types enabled
- **API Documentation**: Swagger/OpenAPI with XML documentation comments
- **Database**: MongoDB (optional) for storing service registrations and validation history
- **Validation Engine**: 
  - JSON Schema validation using Newtonsoft.Json.Schema (v4.0.1) and JsonSchema.Net (v8.0.5)
  - OpenAPI specification parsing and validation
  - Automated endpoint discovery and testing
  - Response schema validation against HSDS-UK standards
- **Observability**: OpenTelemetry integration with OTLP export for metrics and distributed tracing
- **Health Checks**: ASP.NET Core Health Checks with MongoDB and external URL monitoring
- **Security**: Rate limiting, CORS configuration, configurable SSL validation

### Key Projects

- **OpenReferralApi**: Main ASP.NET Core Web API application
- **OpenReferralApi.Core**: Core business logic, models, and shared services
- **OpenReferralApi.Tests**: Comprehensive unit and integration tests

### Core Services

- **OpenApiValidationService**: Orchestrates OpenAPI spec validation and endpoint testing
- **OpenApiDiscoveryService**: Discovers and parses OpenAPI specifications from URLs
- **JsonValidatorService**: Validates JSON responses against HSDS-UK schemas
- **SchemaResolverService**: Resolves JSON Schema definitions and creates JSchema objects
- **RequestProcessingService**: HTTP client management with caching and timeout handling
- **PathParsingService**: URL and path parameter parsing utilities
- **OpenApiToValidationResponseMapper**: Maps validation results to response formats
- **FeedValidationBackgroundService**: Schedules and executes automatic feed validation at midnight or fixed intervals

### Deployment

- **Containerization**: Multi-stage Docker builds with Linux-based images
- **Cloud Platform**: Heroku-ready with dynamic port configuration
- **Orchestration**: Kubernetes-compatible health check endpoints
- **CORS**: Configurable cross-origin resource sharing for frontend integration

## Documentation

For detailed information about specific components, see:

- [Technical Architecture](https://github.com/tpximpact/OpenReferralApi/wiki/ARCHITECTURE)
- [Development Setup](https://github.com/tpximpact/OpenReferralApi/wiki/DEVELOPMENT-SETUP)
- [Contributing Guide](https://github.com/tpximpact/OpenReferralApi/wiki/CONTRIBUTING)
- [Developer Walkthrough](https://github.com/tpximpact/OpenReferralApi/wiki/DEVELOPER-WALKTHROUGH)
- [Legacy documentation and design decisions](docs/legacy-documentation-and-design-decisions.md)

### API Documentation

When running locally in development mode, interactive API documentation is available at:
- **Swagger UI**: `http://localhost:5000/` (or your configured port)
- **OpenAPI Spec**: `http://localhost:5000/swagger/v1/swagger.json`

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/tpximpact/OpenReferralApi.git
   cd OpenReferralApi
   ```

2. **Run with Docker**:
   ```bash
   docker-compose up
   ```

3. **Or run with .NET CLI**:
   ```bash
   dotnet restore
   dotnet run --project OpenReferralApi/OpenReferralApi.csproj
   ```

4. **Access Swagger UI**: Open `http://localhost:5000` in your browser

## Authentication

The OpenReferral API validation service supports multiple authentication methods for testing protected API endpoints. Authentication can be configured when making validation requests to ensure the validator can access secured endpoints.

### Authentication Types

#### API Key Authentication

Use API keys passed via HTTP headers (default header: `X-API-Key`):

```json
{
  "openApiSchema": {
    "url": "https://api.example.com/openapi.json"
  },
  "baseUrl": "https://api.example.com",
  "dataSourceAuth": {
    "apiKey": "your-api-key-here",
    "apiKeyHeader": "X-API-Key"
  },
  "options": {
    "skipAuthentication": false
  }
}
```

The `apiKeyHeader` field is optional and defaults to `X-API-Key`. You can customize it for APIs that use different header names (e.g., `Api-Key`, `Authorization`, `X-Auth-Token`).

#### Bearer Token Authentication

Use bearer tokens for OAuth 2.0 or JWT-based authentication:

```json
{
  "openApiSchema": {
    "url": "https://api.example.com/openapi.json"
  },
  "baseUrl": "https://api.example.com",
  "dataSourceAuth": {
    "bearerToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "options": {
    "skipAuthentication": false
  }
}
```

This adds an `Authorization: Bearer <token>` header to all endpoint requests.

#### Basic Authentication

Use HTTP Basic Authentication with username and password:

```json
{
  "openApiSchema": {
    "url": "https://api.example.com/openapi.json"
  },
  "baseUrl": "https://api.example.com",
  "dataSourceAuth": {
    "basicAuth": {
      "username": "your-username",
      "password": "your-password"
    }
  },
  "options": {
    "skipAuthentication": false
  }
}
```

Credentials are Base64-encoded and sent in the `Authorization: Basic <credentials>` header.

#### Custom Headers

Add any custom HTTP headers required by your API:

```json
{
  "openApiSchema": {
    "url": "https://api.example.com/openapi.json"
  },
  "baseUrl": "https://api.example.com",
  "dataSourceAuth": {
    "customHeaders": {
      "X-Client-Id": "client-123",
      "X-Request-Id": "req-456",
      "X-Custom-Auth": "custom-value"
    }
  },
  "options": {
    "skipAuthentication": false
  }
}
```

Custom headers are added to all endpoint requests and can be combined with other authentication methods.

#### Multiple Authentication Methods

You can combine multiple authentication methods in a single request:

```json
{
  "openApiSchema": {
    "url": "https://api.example.com/openapi.json"
  },
  "baseUrl": "https://api.example.com",
  "dataSourceAuth": {
    "bearerToken": "your-jwt-token",
    "customHeaders": {
      "X-Client-Id": "client-123",
      "X-Tenant-Id": "tenant-456"
    }
  },
  "options": {
    "skipAuthentication": false
  }
}
```

All specified authentication methods will be applied to endpoint requests.

### Skipping Authentication

By default, authentication is skipped (`skipAuthentication: true`) to allow testing public endpoints. To enable authentication for protected endpoints, explicitly set `skipAuthentication: false`:

```json
{
  "options": {
    "skipAuthentication": false
  }
}
```

### Security Considerations

- **Never commit credentials**: Credentials should be injected via environment variables, secrets management, or secure configuration systems
- **Use HTTPS**: Always validate APIs over HTTPS in production to protect credentials in transit
- **Token rotation**: Refresh tokens regularly and implement proper token lifecycle management
- **Least privilege**: Use credentials with minimal required permissions for validation tasks
- **Audit logging**: Monitor authentication usage and failed attempts for security auditing

### Example: Complete Validation Request with Authentication

```bash
curl -X POST http://localhost:5000/api/validate/openapi \
  -H "Content-Type: application/json" \
  -d '{
    "openApiSchemaUrl": "https://api.example.com/openapi.json",
    "baseUrl": "https://api.example.com",
    "dataSourceAuth": {
      "bearerToken": "your-jwt-token-here"
    },
    "options": {
      "skipAuthentication": false,
      "testEndpoints": true,
      "validateSpecification": true,
      "timeoutSeconds": 30,
      "maxConcurrentRequests": 5
    }
  }'
```

## Community & Support

### HSDS Community

This project builds upon the work of the open Human Services Data Specification (HSDS) community. The HSDS standard was developed collaboratively by organizations and individuals committed to improving access to health and human services.

For questions, discussions, and contributions related to ORUK or the HSDS standard:

- **Community Forum**: [forum.openreferral.org](https://forum.openreferral.org/)
- **Open Referral Global**: [openreferral.org](https://openreferral.org/)
- **Open Referral UK**: [openreferraluk.org](https://openreferraluk.org/)

### Contributing

We welcome contributions from the community! The Open Referral network is built on collaboration and shared expertise.

**For issues specific to this API**, please use the [issues page](https://github.com/tpximpact/OpenReferralApi/issues). Consolidating issues in one place helps us track and respond more efficiently.

**For broader HSDS/ORUK standard discussions**, please post to the [community forums](https://forum.openreferral.org/) where the active community can provide support and guidance.

See [legacy documentation and design decisions](docs/legacy-documentation-and-design-decisions.md) for background and notes.

## License

### Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)

The Human Services Data Specification UK (HSDS-UK) schema, standard documentation, and associated materials are licensed under the **Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)**.

This allows you to:
- **Share**: Copy and redistribute the material in any medium or format
- **Adapt**: Remix, transform, and build upon the material for any purpose, even commercially

Under the following terms:
- **Attribution**: You must give appropriate credit, provide a link to the license, and indicate if changes were made
- **ShareAlike**: If you remix, transform, or build upon the material, you must distribute your contributions under the same license

Please refer to the [LICENSE](/LICENSE) file for full details.

### BSD 3-Clause License

The functional API code and software implementation are licensed under the **BSD 3-Clause License**.

This permissive license allows you to use, modify, and distribute the code with minimal restrictions, provided that copyright notices are retained.

Please refer to the [LICENSE-BSD](/LICENSE-BSD) file for full details.

---

**Acknowledgments**: This project is made possible by the collaborative efforts of the Open Referral community, local government partners, and the broader open data ecosystem working to improve access to health and human services information.

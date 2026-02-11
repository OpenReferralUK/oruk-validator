using System;
using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Request model for initiating OpenAPI specification validation and testing
/// Contains all necessary information to validate specs and optionally test live endpoints
/// </summary>
public class OpenApiValidationRequest
{

    /// <summary>
    /// OpenAPI schema configuration including URL and optional authentication
    /// Used to fetch and authenticate access to the OpenAPI specification
    /// If null, the schema URL will be discovered from the baseUrl
    /// </summary>
    [JsonProperty("openApiSchema")]
    public OpenApiSchema? OpenApiSchema { get; set; }

    /// <summary>
    /// Base URL of the live API server for endpoint testing
    /// Required if endpoint testing is enabled in options
    /// Should include protocol (http/https) and may include port (e.g., "https://api.example.com:8080")
    /// </summary>
    [JsonProperty("baseUrl")]
    public string? BaseUrl { get; set; }

    /// <summary>
    /// Authentication credentials and configuration for accessing the API server during endpoint testing
    /// Supports API keys, bearer tokens, basic auth, and custom headers
    /// Required if endpoint testing is enabled and the API requires authentication for access
    /// </summary>
    [JsonProperty("dataSourceAuth")]
    public DataSourceAuthentication? DataSourceAuth { get; set; }

    /// <summary>
    /// Configuration options controlling validation behavior and endpoint testing
    /// Determines what types of validation and testing to perform
    /// If null, default options will be used (specification validation only)
    /// </summary>
    [JsonProperty("options")]
    public OpenApiValidationOptions? Options { get; set; }

    /// <summary>
    /// Internal property to pass the profile discovery reason from discovery to validation.
    /// This is not part of the public API request and should not be set by clients.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string? ProfileReason { get; set; }
}

/// <summary>
/// Represents authentication credentials and configuration for accessing the API server during endpoint testing
/// </summary>
public class DataSourceAuthentication
{
    [DefaultValue("")]
    [JsonProperty("apiKey")]
    public string? ApiKey { get; set; }

    [DefaultValue("X-API-Key")]
    [JsonProperty("apiKeyHeader")]
    public string ApiKeyHeader { get; set; } = "X-API-Key";

    [DefaultValue("")]
    [JsonProperty("bearerToken")]
    public string? BearerToken { get; set; }

    [JsonProperty("basicAuth")]
    public BasicAuthentication? BasicAuth { get; set; }

    [JsonProperty("customHeaders")]
    public Dictionary<string, string>? CustomHeaders { get; set; } = new();
}

/// <summary>
/// Represents basic authentication credentials for HTTP requests
/// </summary>
public class BasicAuthentication
{
    [DefaultValue("")]
    [JsonProperty("username")]
    public string Username { get; set; } = string.Empty;

    [DefaultValue("")]
    [JsonProperty("password")]
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Configuration for OpenAPI schema location and authentication
/// </summary>
public class OpenApiSchema
{
    /// <summary>
    /// URL to fetch the OpenAPI specification from (JSON or YAML)
    /// The service will download and parse the specification from this URL
    /// Supports HTTP/HTTPS URLs and handles $ref resolution for external references
    /// </summary>
    [JsonProperty("url")]
    public string? Url { get; set; }

    /// <summary>
    /// Authentication credentials and configuration for accessing the OpenAPI schema URL
    /// Used when fetching the OpenAPI specification requires authentication
    /// Supports API keys, bearer tokens, basic auth, and custom headers
    /// If null, schema fetching will be attempted without authentication
    /// </summary>
    [JsonProperty("authentication")]
    public DataSourceAuthentication? Authentication { get; set; }
}

/// <summary>
/// Configuration options for controlling OpenAPI validation and endpoint testing behavior
/// Allows fine-tuning of validation processes and testing parameters
/// </summary>
public class OpenApiValidationOptions
{
    /// <summary>
    /// Whether to perform live endpoint testing against the API server
    /// Set to false for specification-only validation without HTTP requests
    /// Requires a valid BaseUrl in the request when enabled
    /// </summary>
    [JsonProperty("testEndpoints")]
    public bool TestEndpoints { get; set; } = true;

    /// <summary>
    /// Whether to validate the OpenAPI specification structure and compliance
    /// Includes schema validation, security analysis, and quality metrics
    /// Recommended to keep enabled for comprehensive validation
    /// </summary>
    [JsonProperty("validateSpecification")]
    public bool ValidateSpecification { get; set; } = true;

    /// <summary>
    /// Maximum time in seconds to wait for each HTTP request during endpoint testing
    /// Prevents tests from hanging on slow or unresponsive endpoints
    /// Higher values allow for slower APIs but increase total validation time
    /// </summary>
    [DefaultValue(30)]
    [JsonProperty("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum number of HTTP requests to execute simultaneously during endpoint testing
    /// Higher values speed up testing but may overwhelm the target API
    /// Consider the API's rate limits and server capacity when setting this value
    /// </summary>
    [DefaultValue(5)]
    [JsonProperty("maxConcurrentRequests")]
    public int MaxConcurrentRequests { get; set; } = 5;

    /// <summary>
    /// Whether to skip authentication when testing endpoints
    /// Useful for testing public endpoints or when authentication is not available
    /// May result in 401/403 errors for protected endpoints
    /// </summary>
    [DefaultValue(true)]
    [JsonProperty("skipAuthentication")]
    public bool SkipAuthentication { get; set; } = true;

    /// <summary>
    /// Whether to test optional endpoints that are marked as optional in the OpenAPI specification
    /// When true, tests optional endpoints and accepts 404/501 responses as valid for unimplemented features
    /// When false, skips endpoints tagged with "Optional"
    /// </summary>
    [DefaultValue(true)]
    [JsonProperty("testOptionalEndpoints")]
    public bool TestOptionalEndpoints { get; set; } = true;

    /// <summary>
    /// Whether to report non-implemented optional endpoints as warnings instead of errors
    /// When true, optional endpoints returning 404/501 are logged as informational
    /// When false, all endpoint failures are treated as errors regardless of optional status
    /// </summary>
    [DefaultValue(true)]
    [JsonProperty("treatOptionalEndpointsAsWarnings")]
    public bool TreatOptionalEndpointsAsWarnings { get; set; } = true;

    /// <summary>
    /// Whether to include response bodies in `OpenApiValidationResult` output.
    /// When true, `HttpTestResult.responseBody` will contain the actual response content.
    /// When false (default), response bodies are omitted to reduce payload size and avoid exposing sensitive data.
    /// Must be explicitly set to true to include response bodies in validation results.
    /// </summary>
    [DefaultValue(false)]
    [JsonProperty("includeResponseBody")]
    public bool IncludeResponseBody { get; set; } = true;

    /// <summary>
    /// Whether to include detailed test results array in the EndpointTestResult output.
    /// When true, the full `TestResults` collection with all HTTP request/response details will be included.
    /// When false (default), the TestResults array will be excluded to reduce payload size.
    /// Must be explicitly set to true to include detailed test results in validation output.
    /// Note: This only affects the TestResults collection; summary information and validation errors are always included.
    /// </summary>
    [JsonProperty("includeTestResults")]
    public bool IncludeTestResults { get; set; } = true;

    /// <summary>
    /// Whether to return the raw OpenApiValidationResult format or map to the standard ValidationResponse format.
    /// When true, returns the raw OpenApiValidationResult with comprehensive details.
    /// When false (default), maps to the ValidationResponse format for consistency with other validation endpoints.
    /// The raw format provides more detailed OpenAPI-specific analysis and metrics.
    /// </summary>
    [JsonProperty("returnRawResult")]
    public bool ReturnRawResult { get; set; } = false;
}

/// <summary>
/// Comprehensive results of OpenAPI specification validation and endpoint testing
/// Contains detailed analysis, test results, quality metrics, and actionable recommendations
/// </summary>
public class OpenApiValidationResult
{
    /// <summary>
    /// Overall validation status indicating if the API specification and endpoints are valid
    /// False if any critical errors are found in specification validation or endpoint testing
    /// Use Summary property for detailed breakdown of success/failure counts
    /// </summary>
    [JsonProperty("isValid")]
    public bool IsValid { get; set; }

    /// <summary>
    /// Detailed results of OpenAPI specification validation and analysis
    /// Includes schema compliance, security analysis, quality metrics, and recommendations
    /// Null if specification validation was disabled in options
    /// </summary>
    [JsonProperty("specificationValidation")]
    public OpenApiSpecificationValidation? SpecificationValidation { get; set; }

    /// <summary>
    /// Results from testing individual API endpoints against the live server
    /// Each item represents one endpoint (path + method combination) with detailed test results
    /// Empty list if endpoint testing was disabled or no testable endpoints were found
    /// </summary>
    [JsonProperty("endpointTests")]
    public List<EndpointTestResult> EndpointTests { get; set; } = new();

    /// <summary>
    /// High-level summary statistics of validation and testing results
    /// Provides quick overview of success rates, performance metrics, and overall health
    /// Useful for dashboards, reports, and automated decision making
    /// </summary>
    [JsonProperty("summary")]
    public OpenApiValidationSummary Summary { get; set; } = new();

    /// <summary>
    /// Total time taken to complete the entire validation and testing process
    /// Includes specification validation, endpoint discovery, and all HTTP requests
    /// Useful for performance monitoring and optimization
    /// </summary>
    [JsonProperty("duration")]
    public TimeSpan Duration { get; set; }

    /// <summary>
    /// Additional metadata about the validation process and environment
    /// Includes timestamps, API information, testing configuration, and version details
    /// Helpful for audit trails, debugging, and result correlation
    /// </summary>
    [JsonProperty("metadata")]
    public OpenApiValidationMetadata? Metadata { get; set; }
}

/// <summary>
/// Represents detailed validation results for an OpenAPI specification, extending base validation with OpenAPI-specific analysis
/// </summary>
public class OpenApiSpecificationValidation : ValidationResultBase
{
    /// <summary>
    /// The version of the OpenAPI specification (e.g., "3.0.0", "3.1.0", "2.0" for Swagger)
    /// Used to determine which validation rules and schemas to apply
    /// </summary>
    [JsonProperty("openApiVersion")]
    public string? OpenApiVersion { get; set; }

    /// <summary>
    /// The title of the API from the info section
    /// Provides the human-readable name of the API for identification and documentation purposes
    /// </summary>
    [JsonProperty("title")]
    public string? Title { get; set; }

    /// <summary>
    /// The version of the API from the info section (not the OpenAPI spec version)
    /// Indicates the API's own versioning scheme (e.g., "1.0.0", "v2.1")
    /// </summary>
    [JsonProperty("version")]
    public string? Version { get; set; }

    /// <summary>
    /// Total number of endpoints (path + HTTP method combinations) defined in the specification
    /// Provides a quick overview of the API's scope and complexity
    /// </summary>
    [JsonProperty("endpointCount")]
    public int EndpointCount { get; set; }

    /// <summary>
    /// Detailed analysis of the specification's schema structure including components, definitions, and references
    /// Helps understand the complexity and organization of data models within the API
    /// </summary>
    [JsonProperty("schemaAnalysis")]
    public OpenApiSchemaAnalysis? SchemaAnalysis { get; set; }

    /// <summary>
    /// Quality metrics measuring documentation completeness, best practices adherence, and overall specification quality
    /// Provides quantifiable measures to improve developer experience and API usability
    /// </summary>
    [JsonProperty("qualityMetrics")]
    public OpenApiQualityMetrics? QualityMetrics { get; set; }

    /// <summary>
    /// Actionable recommendations for improving the specification based on validation results, best practices, and quality analysis
    /// Provides specific guidance for enhancing security, documentation, and compliance
    /// </summary>
    [JsonProperty("recommendations")]
    public List<OpenApiRecommendation> Recommendations { get; set; } = new();
}

/// <summary>
/// Represents the results of testing a single API endpoint, including HTTP tests, validation, and performance metrics
/// </summary>
public class EndpointTestResult
{
    /// <summary>
    /// The URL path of the endpoint being tested (e.g., "/users/{id}", "/orders")
    /// Used to identify which endpoint this result corresponds to
    /// </summary>
    [JsonProperty("path")]
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// The HTTP method used for testing this endpoint (e.g., "GET", "POST", "PUT")
    /// Distinguishes between different operations on the same path
    /// </summary>
    [JsonProperty("method")]
    public string Method { get; set; } = string.Empty;

    /// <summary>
    /// The unique operation identifier from the OpenAPI specification, if provided
    /// Useful for referencing specific operations and generating code/documentation
    /// </summary>
    [JsonProperty("operationId")]
    public string? OperationId { get; set; }

    /// <summary>
    /// The name of the endpoint as defined in the OpenAPI specification
    /// </summary>
    [JsonProperty("name")]
    public string? Name { get; internal set; }

    /// <summary>
    /// Brief description of what this endpoint does, extracted from the OpenAPI specification
    /// Provides context for understanding the endpoint's purpose
    /// </summary>
    [JsonProperty("summary")]
    public string? Summary { get; set; }
    
    /// <summary>
    /// Indicates whether this endpoint is marked as optional in the OpenAPI specification
    /// </summary>
    [JsonProperty("isOptional")]
    public bool IsOptional { get; internal set; }
    
    /// <summary>
    /// Indicates whether actual HTTP testing was performed on this endpoint
    /// False if testing was skipped due to configuration, errors, or missing requirements
    /// </summary>
    [JsonProperty("isTested")]
    public bool IsTested { get; set; }

    /// <summary>
    /// Overall status of the endpoint test ("Success", "Failed", "Error", "NotTested")
    /// Provides a quick summary of the testing outcome for dashboard/reporting purposes
    /// </summary>
    [JsonProperty("status")]
    public string Status { get; set; } = "NotTested";

    /// <summary>
    /// Collection of HTTP test results for this endpoint, including request/response details
    /// May contain multiple results if the endpoint was tested with different parameters or conditions
    /// </summary>
    [JsonProperty("testResults")]
    public List<HttpTestResult> TestResults { get; set; } = new();

}

/// <summary>
/// Represents the detailed results of a single HTTP request/response test, including timing, validation, and compliance data
/// </summary>
public class HttpTestResult
{
    /// <summary>
    /// The complete URL that was requested during testing, including query parameters
    /// Useful for debugging and reproducing test scenarios
    /// </summary>
    [JsonProperty("requestUrl")]
    public string RequestUrl { get; set; } = string.Empty;

    /// <summary>
    /// The HTTP method used for the request (GET, POST, PUT, DELETE, etc.)
    /// Indicates the type of operation that was tested
    /// </summary>
    [JsonProperty("requestMethod")]
    public string RequestMethod { get; set; } = string.Empty;

    /// <summary>
    /// The request body content that was sent (for POST, PUT, PATCH requests)
    /// Contains the actual data payload used in testing
    /// </summary>
    [JsonProperty("requestBody")]
    public string? RequestBody { get; set; }

    /// <summary>
    /// HTTP status code returned by the server (200, 404, 500, etc.)
    /// Indicates whether the request was successful and how the server responded
    /// </summary>
    [JsonProperty("responseStatusCode")]
    public int? ResponseStatusCode { get; set; }

    /// <summary>
    /// The response body content returned by the server
    /// Contains the actual data returned by the API endpoint
    /// </summary>
    [JsonProperty("responseBody")]
    public string? ResponseBody { get; set; }

    /// <summary>
    /// Total time taken for the complete request-response cycle
    /// Critical for performance analysis and SLA compliance monitoring
    /// </summary>
    [JsonProperty("responseTime")]
    public TimeSpan ResponseTime { get; set; }

    /// <summary>
    /// Detailed performance metrics for this specific HTTP request/response
    /// </summary>
    [JsonProperty("performanceMetrics")]
    public EndpointPerformanceMetrics? PerformanceMetrics { get; set; }

    /// <summary>
    /// Whether the HTTP request was considered successful based on status code and expectations
    /// Typically true for 2xx status codes, but may vary based on testing configuration
    /// </summary>
    [JsonProperty("isSuccess")]
    public bool IsSuccess { get; set; }

    /// <summary>
    /// Error message if the request failed or encountered issues
    /// Provides detailed information about what went wrong during testing
    /// </summary>
    [JsonProperty("errorMessage")]
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// The specific ID value used for testing parameterized endpoints
    /// Only populated when testing endpoints with path parameters like /services/{id}
    /// </summary>
    [JsonProperty("testedId")]
    public string? TestedId { get; set; }

    /// <summary>
    /// Results from validating the response against the OpenAPI specification
    /// Includes schema compliance and data structure validation
    /// </summary>
    [JsonProperty("validationResult")]
    public ValidationResult? ValidationResult { get; set; }
}

/// <summary>
/// Detailed performance breakdown for HTTP request/response timing analysis
/// </summary>
public class EndpointPerformanceMetrics
{
    /// <summary>
    /// Time spent resolving the domain name to an IP address
    /// High values may indicate DNS issues or slow DNS servers
    /// </summary>
    [JsonProperty("dnsLookup")]
    public TimeSpan DnsLookup { get; set; }

    /// <summary>
    /// Time spent establishing the TCP connection to the server
    /// High values may indicate network latency or connectivity issues
    /// </summary>
    [JsonProperty("tcpConnection")]
    public TimeSpan TcpConnection { get; set; }

    /// <summary>
    /// Time spent on TLS/SSL handshake for HTTPS connections
    /// High values may indicate SSL configuration issues or certificate problems
    /// </summary>
    [JsonProperty("tlsHandshake")]
    public TimeSpan TlsHandshake { get; set; }

    /// <summary>
    /// Time spent by the server processing the request and generating the response
    /// High values indicate server-side performance bottlenecks
    /// </summary>
    [JsonProperty("serverProcessing")]
    public TimeSpan ServerProcessing { get; set; }

    /// <summary>
    /// Time spent transferring the response content from server to client
    /// High values may indicate large response sizes or bandwidth limitations
    /// </summary>
    [JsonProperty("contentTransfer")]
    public TimeSpan ContentTransfer { get; set; }

}

/// <summary>
/// Results of security-specific tests performed on an endpoint
/// </summary>
public class SecurityTestResult
{
    /// <summary>
    /// Type of security test performed (e.g., "Authentication", "Authorization", "InputValidation")
    /// Categorizes the security aspect being tested
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Whether the security test passed successfully
    /// False indicates a potential security vulnerability or misconfiguration
    /// </summary>
    [JsonProperty("passed")]
    public bool Passed { get; set; }

    /// <summary>
    /// Detailed information about the security test results
    /// Includes specifics about what was tested and any issues found
    /// </summary>
    [JsonProperty("details")]
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// Detailed validation results for request or response schema compliance
/// </summary>
public class SchemaValidationDetail
{
    /// <summary>
    /// Where this validation was applied ("request" or "response")
    /// Distinguishes between input validation and output validation results
    /// </summary>
    [JsonProperty("location")]
    public string Location { get; set; } = string.Empty;

    /// <summary>
    /// Overall validation status ("Valid", "Invalid", "Skipped")
    /// Provides a quick summary of the validation outcome
    /// </summary>
    [JsonProperty("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>
    /// Specific validation errors found during schema checking
    /// Details about data structure violations or type mismatches
    /// Use the Severity property on ValidationError to distinguish between errors ("Error") and warnings ("Warning")
    /// </summary>
    [JsonProperty("errors")]
    public List<ValidationError> Errors { get; set; } = new();
}

/// <summary>
/// High-level summary statistics and metrics from OpenAPI validation and endpoint testing
/// Provides key performance indicators and success rates for quick assessment
/// </summary>
public class OpenApiValidationSummary
{
    /// <summary>
    /// Total number of API endpoints discovered in the OpenAPI specification
    /// Represents the complete API surface area defined in the specification
    /// Used as the denominator for calculating test coverage percentages
    /// </summary>
    [JsonProperty("totalEndpoints")]
    public int TotalEndpoints { get; set; }

    /// <summary>
    /// Number of endpoints that were actually tested against the live API server
    /// May be less than TotalEndpoints if testing was limited by configuration or errors
    /// Indicates the scope of live validation performed
    /// </summary>
    [JsonProperty("testedEndpoints")]
    public int TestedEndpoints { get; set; }

    /// <summary>
    /// Number of endpoint tests that completed successfully without errors
    /// Success is typically defined as receiving expected HTTP status codes (2xx)
    /// Higher numbers indicate better API health and specification accuracy
    /// </summary>
    [JsonProperty("successfulTests")]
    public int SuccessfulTests { get; set; }

    /// <summary>
    /// Number of endpoint tests that failed due to errors or unexpected responses
    /// Includes HTTP errors (4xx, 5xx), network failures, and validation mismatches
    /// Lower numbers indicate better API reliability and specification compliance
    /// </summary>
    [JsonProperty("failedTests")]
    public int FailedTests { get; set; }

    /// <summary>
    /// Number of endpoints that were not tested due to configuration or technical limitations
    /// May include endpoints requiring specific authentication, data, or unsupported methods
    /// Indicates gaps in test coverage that may need manual verification
    /// </summary>
    [JsonProperty("skippedTests")]
    public int SkippedTests { get; set; }

    /// <summary>
    /// Total number of HTTP requests made during endpoint testing
    /// May exceed TestedEndpoints if multiple requests were made per endpoint
    /// Useful for understanding testing load and API request volume
    /// </summary>
    [JsonProperty("totalRequests")]
    public int TotalRequests { get; set; }

    /// <summary>
    /// Average response time across all successful HTTP requests during testing
    /// Provides baseline performance metrics for API responsiveness
    /// Excludes failed requests and timeouts from calculation
    /// </summary>
    [JsonProperty("averageResponseTime")]
    public TimeSpan AverageResponseTime { get; set; }

    /// <summary>
    /// Whether the OpenAPI specification itself passed structural validation
    /// True indicates the specification follows OpenAPI standards and best practices
    /// Independent of endpoint testing results - focuses on specification quality
    /// </summary>
    [JsonProperty("specificationValid")]
    public bool SpecificationValid { get; set; }
}

/// <summary>
/// Metadata information about the OpenAPI validation process and environment
/// Provides context, audit trail, and debugging information for validation results
/// </summary>
public class OpenApiValidationMetadata : IMetadata
{
    /// <summary>
    /// Version of the OpenAPI specification being validated (e.g., "3.0.0", "3.1.0", "2.0")
    /// Extracted from the specification's openapi or swagger field
    /// Used to determine appropriate validation rules and compatibility
    /// </summary>
    [JsonProperty("openApiVersion")]
    public string? OpenApiVersion { get; set; }

    /// <summary>
    /// Title of the API being validated, as specified in the info section
    /// Provides human-readable identification of the API
    /// Useful for reports, logs, and result correlation
    /// </summary>
    [JsonProperty("title")]
    public string? Title { get; set; }

    /// <summary>
    /// Version of the API being validated (not the OpenAPI spec version)
    /// Extracted from the info.version field in the specification
    /// Helps track validation results across different API versions
    /// </summary>
    [JsonProperty("version")]
    public string? Version { get; set; }

    /// <summary>
    /// Base URL of the API server that was tested during endpoint validation
    /// Records the actual server used for live testing
    /// Important for correlating results with specific environments (dev, staging, prod)
    /// </summary>
    [JsonProperty("baseUrl")]
    public string? BaseUrl { get; set; }

    /// <summary>
    /// UTC timestamp when the validation process was initiated
    /// Provides precise timing information for audit trails and result correlation
    /// Used for tracking validation history and scheduling automated checks
    /// </summary>
    [JsonProperty("testTimestamp")]
    public DateTime TestTimestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Total duration of the validation and testing process
    /// Includes specification parsing, validation, and all endpoint testing time
    /// Useful for performance monitoring and optimization of validation workflows
    /// </summary>
    [JsonProperty("testDuration")]
    public TimeSpan TestDuration { get; set; }

    /// <summary>
    /// User-Agent string sent with HTTP requests during endpoint testing
    /// Identifies the validation tool in server logs and analytics
    /// Can be customized for different environments or identification purposes
    /// </summary>
    [JsonProperty("userAgent")]
    public string UserAgent { get; set; } = "OpenReferral-Validator/1.0";

    /// <summary>
    /// Describes how the profile version was discovered (e.g., from version field, openapi_url field, or defaulted)
    /// Provides transparency about the source of the profile determination
    /// </summary>
    internal string? ProfileReason { get; set; }

    /// <summary>
    /// Implements IMetadata.Timestamp interface requirement
    /// Maps to TestTimestamp property for consistency with other metadata implementations
    /// </summary>
    [JsonIgnore]
    public DateTime Timestamp
    {
        get => TestTimestamp;
        set => TestTimestamp = value;
    }
}

/// <summary>
/// Provides detailed analysis of the OpenAPI specification's schema structure and component organization
/// </summary>
public class OpenApiSchemaAnalysis
{
    /// <summary>
    /// Number of component sections found in the specification (typically 1 for OpenAPI 3.x)
    /// Indicates whether the spec uses the modern components structure for reusable elements
    /// </summary>
    [JsonProperty("componentCount")]
    public int ComponentCount { get; set; }

    /// <summary>
    /// Total number of reusable schema definitions (data models)
    /// Represents the complexity of the API's data structures and reusability
    /// </summary>
    [JsonProperty("schemaCount")]
    public int SchemaCount { get; set; }

    /// <summary>
    /// Number of reusable response definitions in the components section
    /// Indicates how well response structures are organized and reused across endpoints
    /// </summary>
    [JsonProperty("responseCount")]
    public int ResponseCount { get; set; }

    /// <summary>
    /// Number of reusable parameter definitions in the components section
    /// Shows the level of parameter standardization and reuse across the API
    /// </summary>
    [JsonProperty("parameterCount")]
    public int ParameterCount { get; set; }

    /// <summary>
    /// Number of reusable request body definitions in the components section
    /// Indicates standardization of input data structures across operations
    /// </summary>
    [JsonProperty("requestBodyCount")]
    public int RequestBodyCount { get; set; }

    /// <summary>
    /// Number of reusable header definitions in the components section
    /// Shows standardization of HTTP headers used across the API
    /// </summary>
    [JsonProperty("headerCount")]
    public int HeaderCount { get; set; }

    /// <summary>
    /// Total number of example definitions found throughout the specification
    /// Higher counts indicate better documentation and testing support
    /// </summary>
    [JsonProperty("exampleCount")]
    public int ExampleCount { get; set; }

    /// <summary>
    /// Number of link definitions for connecting related operations
    /// Indicates the level of HATEOAS (Hypermedia as the Engine of Application State) implementation
    /// </summary>
    [JsonProperty("linkCount")]
    public int LinkCount { get; set; }

    /// <summary>
    /// Number of callback definitions for asynchronous operations
    /// Shows whether the API includes webhook or event-driven capabilities
    /// </summary>
    [JsonProperty("callbackCount")]
    public int CallbackCount { get; set; }

    /// <summary>
    /// Total number of $ref references that have been resolved in the specification
    /// Higher numbers indicate greater use of reusable components and modular design
    /// </summary>
    [JsonProperty("referencesResolved")]
    public int ReferencesResolved { get; set; }

    /// <summary>
    /// List of circular reference paths detected in the schema definitions
    /// Circular references can cause issues in code generation and documentation tools
    /// </summary>
    [JsonProperty("circularReferences")]
    public List<string> CircularReferences { get; set; } = new();
}

/// <summary>
/// Comprehensive analysis of the API's security configuration, schemes, and vulnerabilities
/// </summary>
public class OpenApiSecurityAnalysis
{
    /// <summary>
    /// Total number of security schemes defined in the specification
    /// Indicates the variety of authentication methods supported by the API
    /// </summary>
    [JsonProperty("securitySchemesCount")]
    public int SecuritySchemesCount { get; set; }

    /// <summary>
    /// Detailed information about each security scheme configured in the specification
    /// Provides insight into authentication methods, their security levels, and configurations
    /// </summary>
    [JsonProperty("securitySchemes")]
    public List<SecuritySchemeInfo> SecuritySchemes { get; set; } = new();

    /// <summary>
    /// List of security requirements that apply globally to all endpoints
    /// Shows which authentication methods are required by default across the API
    /// </summary>
    [JsonProperty("globalSecurityRequirements")]
    public List<string> GlobalSecurityRequirements { get; set; } = new();

    /// <summary>
    /// Number of endpoints that have security requirements (either global or operation-specific)
    /// Higher numbers indicate better security coverage across the API
    /// </summary>
    [JsonProperty("endpointsWithSecurity")]
    public int EndpointsWithSecurity { get; set; }

    /// <summary>
    /// Number of endpoints that lack any security requirements
    /// These endpoints are publicly accessible and may represent security risks
    /// </summary>
    [JsonProperty("endpointsWithoutSecurity")]
    public int EndpointsWithoutSecurity { get; set; }

    /// <summary>
    /// List of security-related recommendations for improving the API's security posture
    /// Includes suggestions for authentication improvements, vulnerability mitigation, and best practices
    /// </summary>
    [JsonProperty("securityRecommendations")]
    public List<string> SecurityRecommendations { get; set; } = new();
}

/// <summary>
/// Detailed information about a specific security scheme defined in the OpenAPI specification
/// </summary>
public class SecuritySchemeInfo
{
    /// <summary>
    /// The name/key of the security scheme as defined in the specification
    /// Used to reference this scheme in security requirements
    /// </summary>
    [JsonProperty("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// The type of security scheme (apiKey, http, oauth2, openIdConnect, mutualTLS)
    /// Determines the authentication mechanism and security properties
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// The HTTP authentication scheme (basic, bearer, digest, etc.) for 'http' type schemes
    /// Specifies the specific HTTP auth method when using HTTP-based authentication
    /// </summary>
    [JsonProperty("scheme")]
    public string? Scheme { get; set; }

    /// <summary>
    /// Format hint for bearer tokens (e.g., "JWT") when using bearer authentication
    /// Helps clients understand the expected token format
    /// </summary>
    [JsonProperty("bearerFormat")]
    public string? BearerFormat { get; set; }

    /// <summary>
    /// Human-readable description of the security scheme
    /// Provides context about how and when this authentication method should be used
    /// </summary>
    [JsonProperty("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Whether this security scheme is considered secure by modern standards
    /// False for schemes like basic auth over HTTP, API keys in URLs, etc.
    /// </summary>
    [JsonProperty("isSecure")]
    public bool IsSecure { get; set; }
}

/// <summary>
/// Comprehensive quality metrics measuring documentation completeness, best practices adherence, and developer experience
/// </summary>
public class OpenApiQualityMetrics
{
    /// <summary>
    /// Percentage of endpoints that have meaningful descriptions (0-100)
    /// Higher percentages indicate better documentation quality and developer experience
    /// </summary>
    [JsonProperty("documentationCoverage")]
    public double DocumentationCoverage { get; set; }

    /// <summary>
    /// Number of endpoints that include description fields
    /// Descriptions help developers understand the purpose and behavior of each endpoint
    /// </summary>
    [JsonProperty("endpointsWithDescription")]
    public int EndpointsWithDescription { get; set; }

    /// <summary>
    /// Number of endpoints that include summary fields
    /// Summaries provide quick overviews of endpoint functionality
    /// </summary>
    [JsonProperty("endpointsWithSummary")]
    public int EndpointsWithSummary { get; set; }

    /// <summary>
    /// Number of endpoints that include request or response examples
    /// Examples are crucial for understanding expected data formats and testing
    /// </summary>
    [JsonProperty("endpointsWithExamples")]
    public int EndpointsWithExamples { get; set; }

    /// <summary>
    /// Number of parameters that include description fields
    /// Parameter descriptions help developers understand input requirements
    /// </summary>
    [JsonProperty("parametersWithDescription")]
    public int ParametersWithDescription { get; set; }

    /// <summary>
    /// Total number of parameters across all endpoints
    /// Used to calculate parameter documentation coverage percentages
    /// </summary>
    [JsonProperty("totalParameters")]
    public int TotalParameters { get; set; }

    /// <summary>
    /// Number of schema definitions that include description fields
    /// Schema descriptions help developers understand data model purposes and constraints
    /// </summary>
    [JsonProperty("schemasWithDescription")]
    public int SchemasWithDescription { get; set; }

    /// <summary>
    /// Total number of schema definitions in the specification
    /// Used to calculate schema documentation coverage percentages
    /// </summary>
    [JsonProperty("totalSchemas")]
    public int TotalSchemas { get; set; }

    /// <summary>
    /// Number of response status codes that include description fields
    /// Response descriptions help developers understand when and why different status codes occur
    /// </summary>
    [JsonProperty("responseCodesDocumented")]
    public int ResponseCodesDocumented { get; set; }

    /// <summary>
    /// Total number of response status codes defined across all endpoints
    /// Used to calculate response documentation coverage percentages
    /// </summary>
    [JsonProperty("totalResponseCodes")]
    public int TotalResponseCodes { get; set; }

    /// <summary>
    /// Overall quality score (0-100) based on weighted documentation, examples, and best practices
    /// Combines multiple quality factors into a single, actionable metric for specification improvement
    /// </summary>
    [JsonProperty("qualityScore")]
    public double QualityScore { get; set; }
}

/// <summary>
/// Represents an actionable recommendation for improving the OpenAPI specification based on analysis results
/// </summary>
public class OpenApiRecommendation
{
    /// <summary>
    /// The type of recommendation ("Error", "Warning", "Improvement", "Security", "BestPractice")
    /// Categorizes the recommendation by its nature and urgency level
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// The category this recommendation falls under ("Validation", "Documentation", "Security", "Performance", "Legal")
    /// Groups related recommendations for easier organization and prioritization
    /// </summary>
    [JsonProperty("category")]
    public string Category { get; set; } = string.Empty;

    /// <summary>
    /// The priority level of this recommendation ("High", "Medium", "Low")
    /// Helps teams prioritize which improvements to address first
    /// </summary>
    [JsonProperty("priority")]
    public string Priority { get; set; } = string.Empty;

    /// <summary>
    /// A clear, descriptive message explaining what needs to be addressed
    /// Provides the specific issue or improvement opportunity identified
    /// </summary>
    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// The specific path or location in the specification where this recommendation applies
    /// Helps developers quickly locate and fix the identified issue (e.g., "info.description", "paths./users.get")
    /// </summary>
    [JsonProperty("path")]
    public string? Path { get; set; }

    /// <summary>
    /// Specific action steps that should be taken to address this recommendation
    /// Provides concrete guidance on how to implement the suggested improvement
    /// </summary>
    [JsonProperty("actionRequired")]
    public string? ActionRequired { get; set; }

    /// <summary>
    /// Description of the positive impact that implementing this recommendation will have
    /// Explains the benefits and why this change is worth making
    /// </summary>
    [JsonProperty("impact")]
    public string? Impact { get; set; }
}

/// <summary>
/// Result of validating an optional endpoint response
/// </summary>
public class OptionalEndpointValidationResult
{
    [JsonProperty("isOptional")]
    public bool IsOptional { get; set; }

    [JsonProperty("validationStatus")]
    public OptionalEndpointStatus ValidationStatus { get; set; }

    [JsonProperty("statusCode")]
    public int StatusCode { get; set; }

    [JsonProperty("category")]
    public string? Category { get; set; }

    [JsonProperty("isValid")]
    public bool IsValid { get; set; }

    [JsonProperty("requiresSchemaValidation")]
    public bool RequiresSchemaValidation { get; set; }

    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// Status of an optional endpoint validation
/// </summary>
public enum OptionalEndpointStatus
{
    Required,        // Endpoint is required and must be implemented
    Implemented,     // Optional endpoint is implemented
    NotImplemented,  // Optional endpoint is not implemented (acceptable)
    Error            // Optional endpoint returned an error
}

using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

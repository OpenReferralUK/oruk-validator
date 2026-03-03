using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

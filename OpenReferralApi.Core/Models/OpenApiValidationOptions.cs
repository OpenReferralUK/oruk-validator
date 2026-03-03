using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

    /// <summary>
    /// Whether to report fields in endpoint responses that are not defined in the schema.
    /// When true, validates response data against the schema and reports any fields that exist in the response
    /// but are not defined in the schema as informational messages.
    /// When false (default), only standard schema validation is performed.
    /// Useful for identifying undocumented fields, schema drift, or incomplete specifications.
    /// </summary>
    [JsonProperty("reportAdditionalFields")]
    public bool ReportAdditionalFields { get; set; } = false;
}

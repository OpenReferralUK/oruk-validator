using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

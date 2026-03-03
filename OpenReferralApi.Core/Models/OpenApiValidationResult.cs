using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

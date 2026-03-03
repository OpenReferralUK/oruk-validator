using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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

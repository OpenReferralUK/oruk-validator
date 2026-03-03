using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

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
    public SchemaAnalysis? SchemaAnalysis { get; set; }

    /// <summary>
    /// Quality metrics measuring documentation completeness, best practices adherence, and overall specification quality
    /// Provides quantifiable measures to improve developer experience and API usability
    /// </summary>
    [JsonProperty("qualityMetrics")]
    public QualityMetrics? QualityMetrics { get; set; }

    /// <summary>
    /// Actionable recommendations for improving the specification based on validation results, best practices, and quality analysis
    /// Provides specific guidance for enhancing security, documentation, and compliance
    /// </summary>
    [JsonProperty("recommendations")]
    public List<Recommendation> Recommendations { get; set; } = new();
}

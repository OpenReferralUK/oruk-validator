using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents an actionable recommendation for improving the OpenAPI specification based on analysis results
/// </summary>
public class Recommendation
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

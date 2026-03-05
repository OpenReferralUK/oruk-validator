using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents the mapped validation response returned by the OpenAPI validation service
/// </summary>
public class OpenReferralUKValidationResponse
{
    /// <summary>
    /// Service information and overall validation status
    /// </summary>
    [JsonProperty("service")]
    public ServiceInfo Service { get; set; } = new();

    /// <summary>
    /// Collection of test suites containing endpoint validation results
    /// </summary>
    [JsonProperty("testSuites")]
    public List<object> TestSuites { get; set; } = new();
}

/// <summary>
/// Contains service metadata and overall validation status
/// </summary>
public class ServiceInfo
{
    /// <summary>
    /// The base URL of the service being validated
    /// </summary>
    [JsonProperty("url")]
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// Whether the service passed validation
    /// </summary>
    [JsonProperty("isValid")]
    public bool IsValid { get; set; }

    /// <summary>
    /// The OpenAPI specification version (e.g., "3.0.0", "2.0")
    /// </summary>
    [JsonProperty("profile")]
    public string Profile { get; set; } = "Unknown";

    /// <summary>
    /// Reason or explanation for the profile version
    /// </summary>
    [JsonProperty("profileReason")]
    public string ProfileReason { get; set; } = "Unknown";
}

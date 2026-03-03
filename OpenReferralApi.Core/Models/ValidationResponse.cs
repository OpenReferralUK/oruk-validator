namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents the mapped validation response returned by the OpenAPI validation service
/// </summary>
public class OpenReferralUKValidationResponse
{
    /// <summary>
    /// Service information and overall validation status
    /// </summary>
    public ServiceInfo Service { get; set; } = new();

    /// <summary>
    /// Collection of test suites containing endpoint validation results
    /// </summary>
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
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// Whether the service passed validation
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// The OpenAPI specification version (e.g., "3.0.0", "2.0")
    /// </summary>
    public string Profile { get; set; } = "Unknown";

    /// <summary>
    /// Reason or explanation for the profile version
    /// </summary>
    public string ProfileReason { get; set; } = "Unknown";
}

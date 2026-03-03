using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Results of security-specific tests performed on an endpoint
/// </summary>
public class SecurityTestResult
{
    /// <summary>
    /// Type of security test performed (e.g., "Authentication", "Authorization", "InputValidation")
    /// Categorizes the security aspect being tested
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Whether the security test passed successfully
    /// False indicates a potential security vulnerability or misconfiguration
    /// </summary>
    [JsonProperty("passed")]
    public bool Passed { get; set; }

    /// <summary>
    /// Detailed information about the security test results
    /// Includes specifics about what was tested and any issues found
    /// </summary>
    [JsonProperty("details")]
    public string Details { get; set; } = string.Empty;
}

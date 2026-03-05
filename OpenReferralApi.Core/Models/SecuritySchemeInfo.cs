using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Detailed information about a specific security scheme defined in the OpenAPI specification
/// </summary>
public class SecuritySchemeInfo
{
    /// <summary>
    /// The name/key of the security scheme as defined in the specification
    /// Used to reference this scheme in security requirements
    /// </summary>
    [JsonProperty("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// The type of security scheme (apiKey, http, oauth2, openIdConnect, mutualTLS)
    /// Determines the authentication mechanism and security properties
    /// </summary>
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// The HTTP authentication scheme (basic, bearer, digest, etc.) for 'http' type schemes
    /// Specifies the specific HTTP auth method when using HTTP-based authentication
    /// </summary>
    [JsonProperty("scheme")]
    public string? Scheme { get; set; }

    /// <summary>
    /// Format hint for bearer tokens (e.g., "JWT") when using bearer authentication
    /// Helps clients understand the expected token format
    /// </summary>
    [JsonProperty("bearerFormat")]
    public string? BearerFormat { get; set; }

    /// <summary>
    /// Human-readable description of the security scheme
    /// Provides context about how and when this authentication method should be used
    /// </summary>
    [JsonProperty("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Whether this security scheme is considered secure by modern standards
    /// False for schemes like basic auth over HTTP, API keys in URLs, etc.
    /// </summary>
    [JsonProperty("isSecure")]
    public bool IsSecure { get; set; }
}

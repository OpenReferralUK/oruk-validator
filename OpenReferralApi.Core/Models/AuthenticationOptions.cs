namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for authentication behavior
/// </summary>
public class AuthenticationOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "Authentication";

    /// <summary>
    /// Whether to allow user-supplied authentication credentials for OpenAPI schema and data source requests
    /// When enabled, authentication details provided in API requests will be used
    /// When disabled, all requests are made without authentication
    /// Default: false (for security)
    /// </summary>
    public bool AllowUserSuppliedAuth { get; set; } = false;
}

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for security settings
/// </summary>
public class SecurityOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "Security";

    /// <summary>
    /// Whether to validate SSL certificates for HTTPS requests
    /// Set to false only in development/testing environments
    /// Default: true
    /// </summary>
    public bool ValidateSslCertificates { get; set; } = true;

    /// <summary>
    /// Allowed CORS origins
    /// Use "*" to allow all origins (not recommended for production)
    /// Default: ["*"]
    /// </summary>
    public string[] AllowedCorsOrigins { get; set; } = new[] { "*" };
}

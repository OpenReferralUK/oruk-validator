namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for schema caching to reduce external HTTP traffic
/// </summary>
public class CacheOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "Cache";

    /// <summary>
    /// Whether schema caching is enabled
    /// Default: true
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Duration in minutes for which remote schemas are cached
    /// Default: 60 minutes (1 hour)
    /// Set to 0 to cache indefinitely (until memory pressure)
    /// </summary>
    public int ExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Maximum size of the cache in MB
    /// Default: 100 MB
    /// </summary>
    public int MaxSizeMB { get; set; } = 100;

    /// <summary>
    /// Priority for sliding expiration - extends cache lifetime on access
    /// Default: false (uses absolute expiration only)
    /// </summary>
    public bool UseSlidingExpiration { get; set; } = false;

    /// <summary>
    /// Duration in minutes for sliding expiration window
    /// Only used when UseSlidingExpiration is true
    /// Default: 30 minutes
    /// </summary>
    public int SlidingExpirationMinutes { get; set; } = 30;
}

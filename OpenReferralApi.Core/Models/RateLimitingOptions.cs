namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for API rate limiting
/// </summary>
public class RateLimitingOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Maximum number of requests allowed within the time window
    /// Default: 100
    /// </summary>
    public int PermitLimit { get; set; } = 100;

    /// <summary>
    /// Time window in seconds for rate limiting
    /// Default: 60 seconds (1 minute)
    /// </summary>
    public int Window { get; set; } = 60;

    /// <summary>
    /// Maximum number of requests that can be queued
    /// Default: 0 (no queueing)
    /// </summary>
    public int QueueLimit { get; set; } = 0;
}

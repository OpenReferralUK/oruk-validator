namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration for warming commonly used remote schemas into cache.
/// </summary>
public class SchemaWarmupOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "SchemaWarmup";

    /// <summary>
    /// Enables schema warmup on application startup.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Delay before warmup starts so app startup is not blocked.
    /// </summary>
    public int StartupDelaySeconds { get; set; } = 5;

    /// <summary>
    /// List of schema URLs to warm.
    /// </summary>
    public List<string> Urls { get; set; } = new();
}

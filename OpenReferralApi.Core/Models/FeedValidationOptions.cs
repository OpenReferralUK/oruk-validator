namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for background feed validation service
/// </summary>
public class FeedValidationOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "FeedValidation";

    /// <summary>
    /// Whether background feed validation is enabled
    /// Default: false
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Interval in hours between validation runs
    /// Default: 24 hours (once per day)
    /// </summary>
    public double IntervalHours { get; set; } = 24;

    /// <summary>
    /// Whether to schedule validation runs at midnight
    /// When true, first run will wait until midnight
    /// Default: true
    /// </summary>
    public bool RunAtMidnight { get; set; } = true;
}

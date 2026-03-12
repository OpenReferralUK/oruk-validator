namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for semantic data auditing.
/// </summary>
public class SemanticDataAuditOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "SemanticDataAudit";

    /// <summary>
    /// Whether semantic auditing endpoints are enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Score below which a record is considered a likely mismatch.
    /// </summary>
    public double MismatchThreshold { get; set; } = 0.4;

    /// <summary>
    /// Required gap between the assigned taxonomy score and a better alternative.
    /// </summary>
    public double MinimumAlternativeGap { get; set; } = 0.25;
}

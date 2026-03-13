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

    /// <summary>
    /// Minimum number of description tokens before a poor-description warning is raised.
    /// </summary>
    public int MinDescriptionTokenCount { get; set; } = 6;

    /// <summary>
    /// Enables placeholder checks for name, description and address fields.
    /// </summary>
    public bool EnablePlaceholderChecks { get; set; } = true;

    /// <summary>
    /// Enables cross-field checks for contact values (e.g. URL in email field).
    /// </summary>
    public bool EnableContactFieldContextChecks { get; set; } = true;

    /// <summary>
    /// Minimum phone digit count for a valid phone value.
    /// </summary>
    public int PhoneMinDigits { get; set; } = 7;

    /// <summary>
    /// Maximum phone digit count for a valid phone value.
    /// </summary>
    public int PhoneMaxDigits { get; set; } = 15;

    /// <summary>
    /// Enables duplicate and near-duplicate service detection across a run.
    /// </summary>
    public bool EnableDuplicateDetection { get; set; } = true;

    /// <summary>
    /// Similarity score at or above which two services are flagged as likely duplicates.
    /// </summary>
    public double DuplicateSimilarityThreshold { get; set; } = 0.92;

    /// <summary>
    /// Similarity score at or above which two services are flagged as potential near-duplicates.
    /// </summary>
    public double NearDuplicateSimilarityThreshold { get; set; } = 0.78;

    /// <summary>
    /// Additional mismatch threshold applied when strict mode is enabled.
    /// </summary>
    public double StrictModeThresholdAdjustment { get; set; } = 0.1;

    /// <summary>
    /// Additional description token requirement applied when strict mode is enabled.
    /// </summary>
    public int StrictModeDescriptionTokenIncrease { get; set; } = 2;

    /// <summary>
    /// Reduction applied to duplicate thresholds when strict mode is enabled.
    /// </summary>
    public double StrictModeDuplicateThresholdReduction { get; set; } = 0.07;
}

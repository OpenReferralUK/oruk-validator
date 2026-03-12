using System.ComponentModel.DataAnnotations;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Request payload for semantic data auditing.
/// </summary>
public class SemanticDataAuditRequest : IValidatableObject
{
    /// <summary>
    /// Services to audit. Optional when SourceBaseUrl is provided.
    /// </summary>
    public List<SemanticAuditServiceRecord> Services { get; set; } = new();

    /// <summary>
    /// Base URL of the Open Referral data source. When provided, the API will fetch services and taxonomy terms.
    /// </summary>
    public string? SourceBaseUrl { get; set; }

    /// <summary>
    /// Relative path to services endpoint.
    /// </summary>
    public string ServicesPath { get; set; } = "/services";

    /// <summary>
    /// Relative path to taxonomy terms endpoint.
    /// </summary>
    public string TaxonomyTermsPath { get; set; } = "/taxonomy_terms";

    /// <summary>
    /// Optional authentication for data source requests.
    /// </summary>
    public DataSourceAuthentication? DataSourceAuthentication { get; set; }

    /// <summary>
    /// Optional known taxonomy terms used as alternative suggestions.
    /// </summary>
    public List<string> TaxonomyTerms { get; set; } = new();

    /// <summary>
    /// Optional threshold override for this run.
    /// </summary>
    [Range(0, 1)]
    public double? MismatchThreshold { get; set; }

    public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
    {
        if ((Services == null || Services.Count == 0) && string.IsNullOrWhiteSpace(SourceBaseUrl))
        {
            yield return new System.ComponentModel.DataAnnotations.ValidationResult(
                "Provide either at least one service record or SourceBaseUrl.",
                [nameof(Services), nameof(SourceBaseUrl)]);
        }
    }
}

/// <summary>
/// A service record for feed auditing — includes taxonomy, contact, and location data.
/// </summary>
public class SemanticAuditServiceRecord
{
    /// <summary>External service identifier.</summary>
    [Required]
    public string ServiceId { get; set; } = string.Empty;

    public string? ServiceName { get; set; }

    [Required]
    public string ServiceDescription { get; set; } = string.Empty;

    /// <summary>Primary taxonomy term (first entry in TaxonomyTerms, or "Unspecified").</summary>
    public string TaxonomyTerm { get; set; } = string.Empty;

    public List<string> TaxonomyTerms { get; set; } = new();
    public List<string> PhoneNumbers { get; set; } = new();
    public List<string> Emails { get; set; } = new();
    public List<string> Urls { get; set; } = new();
    public string? Address { get; set; }
}

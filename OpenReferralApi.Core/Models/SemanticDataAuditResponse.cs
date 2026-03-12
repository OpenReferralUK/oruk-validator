namespace OpenReferralApi.Core.Models;

/// <summary>
/// Result of semantic auditing across one or more services.
/// </summary>
public class SemanticDataAuditResponse
{
    public int TotalServices { get; set; }
    public int FlaggedServices { get; set; }
    public string AuditEngine { get; set; } = "heuristic";
    public string? DataSourceBaseUrl { get; set; }
    public double MismatchRate => TotalServices == 0 ? 0 : (double)FlaggedServices / TotalServices;
    public List<SemanticAuditFinding> Findings { get; set; } = new();
}

/// <summary>
/// Audit result for a single service record.
/// </summary>
public class SemanticAuditFinding
{
    public string ServiceId { get; set; } = string.Empty;
    public string? ServiceName { get; set; }
    public string TaxonomyTerm { get; set; } = string.Empty;
    public bool IsMismatch { get; set; }
    public double AssignedTermScore { get; set; }
    public string? SuggestedTaxonomyTerm { get; set; }
    public double SuggestedTermScore { get; set; }
    public string Reason { get; set; } = string.Empty;
}

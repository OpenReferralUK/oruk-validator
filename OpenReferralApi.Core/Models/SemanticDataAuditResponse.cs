namespace OpenReferralApi.Core.Models;

public class SemanticDataAuditResponse
{
    public int TotalServices { get; set; }
    public int FlaggedServices { get; set; }
    public int TotalIssues { get; set; }
    public string AuditEngine { get; set; } = "heuristic";
    public string? DataSourceBaseUrl { get; set; }
    public double IssueRate => TotalServices == 0 ? 0 : (double)FlaggedServices / TotalServices;
    public List<SemanticAuditFinding> Findings { get; set; } = new();
}

public class SemanticAuditFinding
{
    public string ServiceId { get; set; } = string.Empty;
    public string? ServiceName { get; set; }
    public bool HasIssues => Issues.Count > 0;
    public List<FeedAuditIssue> Issues { get; set; } = new();
}

public class FeedAuditIssue
{
    /// <summary>
    /// One of: taxonomy_mismatch, missing_contact, poor_description, inconsistent_name, data_inconsistency, invalid_data
    /// </summary>
    public string IssueType { get; set; } = string.Empty;

    /// <summary>error | warning | info</summary>
    public string Severity { get; set; } = "warning";

    public string? AffectedField { get; set; }
    public string Description { get; set; } = string.Empty;
    public string? Suggestion { get; set; }
    public double Confidence { get; set; }
}


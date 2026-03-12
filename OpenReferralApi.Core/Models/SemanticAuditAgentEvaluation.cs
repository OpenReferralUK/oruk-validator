namespace OpenReferralApi.Core.Models;

/// <summary>
/// Result returned by the semantic audit agent for one service-to-taxonomy evaluation.
/// </summary>
public class SemanticAuditAgentEvaluation
{
    public bool IsMismatch { get; set; }
    public double Confidence { get; set; }
    public string? SuggestedTaxonomyTerm { get; set; }
    public string Reason { get; set; } = string.Empty;
}

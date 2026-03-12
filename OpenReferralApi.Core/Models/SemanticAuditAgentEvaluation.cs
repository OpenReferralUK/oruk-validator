namespace OpenReferralApi.Core.Models;

/// <summary>
/// Result returned by the semantic audit agent for one service record.
/// </summary>
public class SemanticAuditAgentEvaluation
{
    public List<FeedAuditIssue> Issues { get; set; } = new();
}

using Azure;
using Azure.AI.OpenAI;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using OpenAI;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

public interface ISemanticAuditAgentService
{
    bool IsEnabled { get; }

    Task<SemanticAuditAgentEvaluation?> EvaluateAsync(
        SemanticAuditServiceRecord service,
        IReadOnlyCollection<string> candidateTerms,
        CancellationToken cancellationToken = default);
}

public class SemanticAuditAgentService : ISemanticAuditAgentService
{
    private readonly SemanticDataAuditLlmOptions _llmOptions;
    private readonly ILogger<SemanticAuditAgentService> _logger;

    public SemanticAuditAgentService(
        IOptions<SemanticDataAuditLlmOptions> llmOptions,
        ILogger<SemanticAuditAgentService> logger)
    {
        _llmOptions = llmOptions.Value;
        _logger = logger;
    }

    public bool IsEnabled =>
        _llmOptions.Enabled
        && !string.IsNullOrWhiteSpace(_llmOptions.ApiKey)
        && !string.IsNullOrWhiteSpace(_llmOptions.DeploymentOrModel)
        && !string.IsNullOrWhiteSpace(_llmOptions.Endpoint);

    public async Task<SemanticAuditAgentEvaluation?> EvaluateAsync(
        SemanticAuditServiceRecord service,
        IReadOnlyCollection<string> candidateTerms,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled)
        {
            return null;
        }

        var agent = BuildAgent();
        var runOptions = new ChatClientAgentRunOptions(new Microsoft.Extensions.AI.ChatOptions
        {
            Temperature = (float)_llmOptions.Temperature,
            MaxOutputTokens = _llmOptions.MaxTokens
        });

        var response = await agent.RunAsync(
            BuildPrompt(service, candidateTerms),
            options: runOptions,
            cancellationToken: cancellationToken);

        var content = response.Text;

        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        var payload = TryParseJsonObject(content);
        if (payload == null)
        {
            _logger.LogWarning("Semantic audit agent did not return parseable JSON.");
            return null;
        }

        var issuesArray = payload["issues"] as JArray;
        if (issuesArray == null)
        {
            _logger.LogWarning("Semantic audit agent response missing 'issues' array.");
            return null;
        }

        var issues = issuesArray.OfType<JObject>().Select(issue => new FeedAuditIssue
        {
            IssueType = issue["issueType"]?.ToString() ?? "unknown",
            Severity = issue["severity"]?.ToString() ?? "warning",
            AffectedField = issue["affectedField"]?.ToString(),
            Description = issue["description"]?.ToString() ?? string.Empty,
            Suggestion = issue["suggestion"]?.ToString(),
            Confidence = Math.Clamp(issue["confidence"]?.Value<double?>() ?? 0, 0, 1)
        }).ToList();

        return new SemanticAuditAgentEvaluation { Issues = issues };
    }

    private AIAgent BuildAgent()
    {
        const string name = "FeedDataAuditorAgent";
        const string instructions = "You are a data auditor. Use the provided tools to verify if the data makes sense. Do not add conversational filler.";
        var provider = _llmOptions.Provider.Trim();

        if (string.Equals(provider, "AzureOpenAI", StringComparison.OrdinalIgnoreCase))
        {
            return new AzureOpenAIClient(
                    new Uri(_llmOptions.Endpoint),
                    new AzureKeyCredential(_llmOptions.ApiKey))
                .GetChatClient(_llmOptions.DeploymentOrModel)
                .AsIChatClient()
                .AsAIAgent(name: name, instructions: instructions);
        }

        return new OpenAIClient(_llmOptions.ApiKey)
            .GetChatClient(_llmOptions.DeploymentOrModel)
            .AsIChatClient()
            .AsAIAgent(name: name, instructions: instructions);
    }

    private static string BuildPrompt(SemanticAuditServiceRecord service, IReadOnlyCollection<string> candidateTerms)
    {
        var taxonomyTerms = service.TaxonomyTerms.Count > 0
            ? string.Join(", ", service.TaxonomyTerms)
            : service.TaxonomyTerm;
        var candidates = string.Join(", ", candidateTerms.Where(x => !string.IsNullOrWhiteSpace(x)).Take(30));
        var phones = string.Join(", ", service.PhoneNumbers);
        var emails = string.Join(", ", service.Emails);
        var urls = string.Join(", ", service.Urls);

        return $"""
Audit this Open Referral service record for data quality issues.
Return ONLY a JSON object with key "issues" containing an array of issues.

Each issue must have:
  issueType (string): taxonomy_mismatch | missing_contact | poor_description | inconsistent_name | data_inconsistency | invalid_data
  severity (string): "error" | "warning" | "info"
  affectedField (string): field with the issue
  description (string): concise problem description
  suggestion (string or null): recommended fix
  confidence (number 0-1)

ServiceId: {service.ServiceId}
ServiceName: {service.ServiceName}
Description: {service.ServiceDescription}
TaxonomyTerms: [{taxonomyTerms}]
PhoneNumbers: [{phones}]
Emails: [{emails}]
Urls: [{urls}]
Address: {service.Address}
CandidateTaxonomyTerms: [{candidates}]
""";
    }

    private static JObject? TryParseJsonObject(string content)
    {
        try
        {
            return JObject.Parse(content);
        }
        catch
        {
            var start = content.IndexOf('{');
            var end = content.LastIndexOf('}');
            if (start < 0 || end <= start)
            {
                return null;
            }

            var candidate = content[start..(end + 1)];
            try
            {
                return JObject.Parse(candidate);
            }
            catch
            {
                return null;
            }
        }
    }
}

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Agents;
using Microsoft.SemanticKernel.ChatCompletion;
using Microsoft.SemanticKernel.Connectors.OpenAI;
using Newtonsoft.Json.Linq;
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

        var kernel = BuildKernel();
        var agent = BuildAgent(kernel);
        var thread = new ChatHistoryAgentThread();
        var message = new ChatMessageContent(AuthorRole.User, BuildPrompt(service, candidateTerms));

        string? content = null;
        await foreach (ChatMessageContent response in agent.InvokeAsync(message, thread, cancellationToken: cancellationToken))
        {
            if (!string.IsNullOrWhiteSpace(response.Content))
            {
                content = response.Content;
            }
        }

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

        var confidence = payload["confidence"]?.Value<double?>() ?? 0;

        return new SemanticAuditAgentEvaluation
        {
            IsMismatch = payload["isMismatch"]?.Value<bool?>() ?? false,
            Confidence = Math.Clamp(confidence, 0, 1),
            SuggestedTaxonomyTerm = payload["suggestedTaxonomyTerm"]?.ToString(),
            Reason = payload["reason"]?.ToString() ?? "Agent completed classification."
        };
    }

    private ChatCompletionAgent BuildAgent(Kernel kernel)
    {
        return new ChatCompletionAgent
        {
            Name = "SemanticTaxonomyAuditAgent",
            Instructions = "You are a data quality agent for Open Referral taxonomy auditing. Return strict JSON only.",
            Kernel = kernel,
            Arguments = BuildAgentArguments()
        };
    }

    private Kernel BuildKernel()
    {
        var builder = Kernel.CreateBuilder();
        var provider = _llmOptions.Provider.Trim();

        if (string.Equals(provider, "AzureOpenAI", StringComparison.OrdinalIgnoreCase))
        {
            builder.AddAzureOpenAIChatCompletion(
                deploymentName: _llmOptions.DeploymentOrModel,
                endpoint: _llmOptions.Endpoint,
                apiKey: _llmOptions.ApiKey);
        }
        else
        {
            builder.AddOpenAIChatCompletion(
                modelId: _llmOptions.DeploymentOrModel,
                apiKey: _llmOptions.ApiKey);
        }

        return builder.Build();
    }

    private KernelArguments BuildAgentArguments()
    {
        return new KernelArguments(new OpenAIPromptExecutionSettings
        {
            Temperature = _llmOptions.Temperature,
            MaxTokens = _llmOptions.MaxTokens
        });
    }

    private static string BuildPrompt(SemanticAuditServiceRecord service, IReadOnlyCollection<string> candidateTerms)
    {
        var candidates = string.Join(", ", candidateTerms.Where(x => !string.IsNullOrWhiteSpace(x)).Take(30));

        return $"""
Evaluate whether the assigned taxonomy term matches this service description.
Return strict JSON with keys: isMismatch (bool), confidence (0-1), suggestedTaxonomyTerm (string or null), reason (string).

ServiceId: {service.ServiceId}
ServiceName: {service.ServiceName}
AssignedTaxonomyTerm: {service.TaxonomyTerm}
ServiceDescription: {service.ServiceDescription}
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

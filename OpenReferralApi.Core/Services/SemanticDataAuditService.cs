using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

public interface ISemanticDataAuditService
{
    Task<SemanticDataAuditResponse> AuditAsync(SemanticDataAuditRequest request, CancellationToken cancellationToken = default);
}

public class SemanticDataAuditService : ISemanticDataAuditService
{
    private static readonly Regex TokenRegex = new("[a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Dictionary<string, string[]> TaxonomyKeywordMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Food Bank"] = ["food", "bank", "meal", "hunger", "groceries", "parcel", "nutrition", "pantry", "voucher", "soup"],
        ["Legal Aid"] = ["legal", "law", "solicitor", "tribunal", "advocacy", "court", "advice", "rights", "litigation", "representation"],
        ["Housing Advice"] = ["housing", "homeless", "tenancy", "landlord", "eviction", "accommodation", "rent", "shelter"],
        ["Mental Health"] = ["mental", "wellbeing", "therapy", "counselling", "anxiety", "depression", "trauma", "psychology"],
        ["Debt Advice"] = ["debt", "arrears", "credit", "loan", "budget", "financial", "bankruptcy", "insolvency"]
    };

    private readonly SemanticDataAuditOptions _options;
    private readonly ISemanticAuditAgentService _semanticAuditAgentService;
    private readonly AuthenticationOptions _authenticationOptions;
    private readonly HttpClient _httpClient;
    private readonly ILogger<SemanticDataAuditService> _logger;

    public SemanticDataAuditService(
        IOptions<SemanticDataAuditOptions> options,
        ISemanticAuditAgentService semanticAuditAgentService,
        IOptions<AuthenticationOptions> authenticationOptions,
        HttpClient httpClient,
        ILogger<SemanticDataAuditService> logger)
    {
        _options = options.Value;
        _semanticAuditAgentService = semanticAuditAgentService;
        _authenticationOptions = authenticationOptions.Value;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<SemanticDataAuditResponse> AuditAsync(SemanticDataAuditRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_options.Enabled)
        {
            throw new InvalidOperationException("Semantic data audit is disabled by configuration.");
        }

        var records = await ResolveServiceRecordsAsync(request, cancellationToken);
        var threshold = request.MismatchThreshold ?? _options.MismatchThreshold;
        var candidateTerms = BuildCandidateTerms(records, request);

        var findings = new List<SemanticAuditFinding>();
        foreach (var service in records)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var llmFinding = await ScoreWithLlmAsync(service, candidateTerms, threshold, cancellationToken);
            findings.Add(llmFinding ?? ScoreWithHeuristic(service, candidateTerms, threshold));
        }

        var engine = _semanticAuditAgentService.IsEnabled ? "microsoft-agent-framework" : "heuristic";

        var response = new SemanticDataAuditResponse
        {
            TotalServices = findings.Count,
            FlaggedServices = findings.Count(x => x.IsMismatch),
            AuditEngine = engine,
            DataSourceBaseUrl = request.SourceBaseUrl,
            Findings = findings
        };

        _logger.LogInformation(
            "Semantic audit completed. Total={TotalServices}, Flagged={FlaggedServices}, Threshold={Threshold}, Engine={Engine}",
            response.TotalServices,
            response.FlaggedServices,
            threshold,
            response.AuditEngine);

        return response;
    }

    private async Task<List<SemanticAuditServiceRecord>> ResolveServiceRecordsAsync(
        SemanticDataAuditRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Services.Count > 0)
        {
            return request.Services;
        }

        if (string.IsNullOrWhiteSpace(request.SourceBaseUrl))
        {
            throw new ArgumentException("SourceBaseUrl is required when Services are not provided.");
        }

        var taxonomyById = await FetchTaxonomyTermsAsync(request, cancellationToken);
        var services = await FetchServicesAsync(request, cancellationToken);

        var records = new List<SemanticAuditServiceRecord>();
        foreach (var service in services.OfType<JObject>())
        {
            var id = service["id"]?.ToString();
            var description = service["description"]?.ToString();
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(description))
            {
                continue;
            }

            var name = service["name"]?.ToString();
            var taxonomyTerms = ExtractServiceTaxonomyTerms(service, taxonomyById);

            if (taxonomyTerms.Count == 0)
            {
                records.Add(new SemanticAuditServiceRecord
                {
                    ServiceId = id,
                    ServiceName = name,
                    ServiceDescription = description,
                    TaxonomyTerm = "Unspecified"
                });
                continue;
            }

            foreach (var taxonomyTerm in taxonomyTerms)
            {
                records.Add(new SemanticAuditServiceRecord
                {
                    ServiceId = id,
                    ServiceName = name,
                    ServiceDescription = description,
                    TaxonomyTerm = taxonomyTerm
                });
            }
        }

        if (records.Count == 0)
        {
            throw new InvalidOperationException("No services with descriptions were found from the configured source.");
        }

        return records;
    }

    private async Task<SemanticAuditFinding?> ScoreWithLlmAsync(
        SemanticAuditServiceRecord service,
        IReadOnlyCollection<string> candidateTerms,
        double threshold,
        CancellationToken cancellationToken)
    {
        if (!_semanticAuditAgentService.IsEnabled)
        {
            return null;
        }

        try
        {
            var evaluation = await _semanticAuditAgentService.EvaluateAsync(service, candidateTerms, cancellationToken);
            if (evaluation == null)
            {
                return null;
            }

            var isMismatch = evaluation.IsMismatch && evaluation.Confidence >= threshold;

            return new SemanticAuditFinding
            {
                ServiceId = service.ServiceId,
                ServiceName = service.ServiceName,
                TaxonomyTerm = service.TaxonomyTerm,
                IsMismatch = isMismatch,
                AssignedTermScore = isMismatch ? Math.Max(0, 1 - evaluation.Confidence) : evaluation.Confidence,
                SuggestedTaxonomyTerm = isMismatch ? evaluation.SuggestedTaxonomyTerm : null,
                SuggestedTermScore = isMismatch ? evaluation.Confidence : 0,
                Reason = evaluation.Reason
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Agent-based evaluation failed for service {ServiceId}. Falling back to heuristic scoring.", service.ServiceId);
            return null;
        }
    }

    private SemanticAuditFinding ScoreWithHeuristic(
        SemanticAuditServiceRecord service,
        IReadOnlyCollection<string> candidateTerms,
        double threshold)
    {
        var descriptionTokens = ExtractTokens(service.ServiceDescription);
        var assignedTermScore = ScoreTerm(service.TaxonomyTerm, descriptionTokens);

        var bestAlternative = candidateTerms
            .Where(t => !string.Equals(t, service.TaxonomyTerm, StringComparison.OrdinalIgnoreCase))
            .Select(term => new
            {
                Term = term,
                Score = ScoreTerm(term, descriptionTokens)
            })
            .OrderByDescending(x => x.Score)
            .FirstOrDefault();

        var bestAlternativeScore = bestAlternative?.Score ?? 0;
        var assignedLooksWeak = assignedTermScore < threshold;
        var alternativeLooksBetter = bestAlternativeScore - assignedTermScore >= _options.MinimumAlternativeGap;
        var isMismatch = assignedLooksWeak && alternativeLooksBetter;

        var reason = isMismatch
            ? $"Assigned term '{service.TaxonomyTerm}' scored {assignedTermScore:F2}, while '{bestAlternative?.Term}' scored {bestAlternativeScore:F2}."
            : $"Assigned term '{service.TaxonomyTerm}' appears semantically consistent (score {assignedTermScore:F2}).";

        return new SemanticAuditFinding
        {
            ServiceId = service.ServiceId,
            ServiceName = service.ServiceName,
            TaxonomyTerm = service.TaxonomyTerm,
            IsMismatch = isMismatch,
            AssignedTermScore = assignedTermScore,
            SuggestedTaxonomyTerm = isMismatch ? bestAlternative?.Term : null,
            SuggestedTermScore = isMismatch ? bestAlternativeScore : 0,
            Reason = reason
        };
    }

    private static IReadOnlyCollection<string> BuildCandidateTerms(
        IReadOnlyCollection<SemanticAuditServiceRecord> records,
        SemanticDataAuditRequest request)
    {
        var terms = records
            .Select(x => x.TaxonomyTerm)
            .Concat(request.TaxonomyTerms)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (terms.Count == 0)
        {
            return TaxonomyKeywordMap.Keys.ToList();
        }

        return terms;
    }

    private static double ScoreTerm(string term, IReadOnlyCollection<string> descriptionTokens)
    {
        if (descriptionTokens.Count == 0)
        {
            return 0;
        }

        var normalizedDescriptionTokens = NormalizeTokens(descriptionTokens);
        var directTermTokens = NormalizeTokens(ExtractTokens(term));

        var directScore = 0d;
        if (directTermTokens.Count > 0)
        {
            var directOverlap = directTermTokens.Count(normalizedDescriptionTokens.Contains);
            directScore = (double)directOverlap / directTermTokens.Count;
        }

        if (!TaxonomyKeywordMap.TryGetValue(term, out var curatedKeywords) || curatedKeywords.Length == 0)
        {
            return directScore;
        }

        var normalizedCuratedKeywords = NormalizeTokens(curatedKeywords);
        var curatedOverlap = normalizedCuratedKeywords.Count(normalizedDescriptionTokens.Contains);

        // Use a small denominator cap so a few strong matches still produce meaningful confidence.
        var curatedDenominator = Math.Min(3, normalizedCuratedKeywords.Count);
        var curatedScore = curatedDenominator == 0 ? 0 : (double)curatedOverlap / curatedDenominator;

        return Math.Max(directScore, curatedScore);
    }

    private static HashSet<string> NormalizeTokens(IEnumerable<string> tokens)
    {
        var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            var value = token.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            normalized.Add(value);

            // Lightweight normalization for plurals (e.g., meals -> meal, parcels -> parcel).
            if (value.Length > 3 && value.EndsWith('s'))
            {
                normalized.Add(value[..^1]);
            }
        }

        return normalized;
    }

    private static IReadOnlyCollection<string> ExtractTokens(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Array.Empty<string>();
        }

        return TokenRegex.Matches(text)
            .Select(match => match.Value.ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }


    private async Task<Dictionary<string, string>> FetchTaxonomyTermsAsync(
        SemanticDataAuditRequest request,
        CancellationToken cancellationToken)
    {
        var token = await FetchJsonAsync(request, request.TaxonomyTermsPath, cancellationToken);
        var array = ExtractArray(token, "taxonomy_terms");

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in array.OfType<JObject>())
        {
            var id = item["id"]?.ToString();
            var name = item["name"]?.ToString();

            if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(name))
            {
                result[id] = name;
            }
        }

        return result;
    }

    private async Task<JArray> FetchServicesAsync(
        SemanticDataAuditRequest request,
        CancellationToken cancellationToken)
    {
        var token = await FetchJsonAsync(request, request.ServicesPath, cancellationToken);
        return ExtractArray(token, "services");
    }

    private async Task<JToken> FetchJsonAsync(
        SemanticDataAuditRequest request,
        string path,
        CancellationToken cancellationToken)
    {
        var url = BuildAbsoluteUrl(request.SourceBaseUrl!, path);
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, url);
        ApplyDataSourceAuthentication(httpRequest, request.DataSourceAuthentication, url);

        var response = await _httpClient.SendAsync(httpRequest, cancellationToken);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return JToken.Parse(content);
    }

    private void ApplyDataSourceAuthentication(
        HttpRequestMessage request,
        DataSourceAuthentication? auth,
        string targetUrl)
    {
        if (auth == null || !_authenticationOptions.AllowUserSuppliedAuth)
        {
            return;
        }

        var targetUri = new Uri(targetUrl);
        if (!string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Skipping user-supplied auth for non-HTTPS semantic audit source URL.");
            return;
        }

        if (!string.IsNullOrWhiteSpace(auth.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.BearerToken);
        }

        if (!string.IsNullOrWhiteSpace(auth.ApiKey))
        {
            request.Headers.TryAddWithoutValidation(auth.ApiKeyHeader, auth.ApiKey);
        }

        if (auth.CustomHeaders == null)
        {
            return;
        }

        foreach (var header in auth.CustomHeaders)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
    }

    private static string BuildAbsoluteUrl(string baseUrl, string path)
    {
        var baseUri = new Uri(baseUrl.EndsWith('/') ? baseUrl : $"{baseUrl}/");
        var relative = path.TrimStart('/');
        return new Uri(baseUri, relative).ToString();
    }

    private static JArray ExtractArray(JToken token, string defaultProperty)
    {
        if (token is JArray directArray)
        {
            return directArray;
        }

        if (token is JObject obj)
        {
            var candidateProperties = new[] { defaultProperty, "data", "items", "results" };
            foreach (var property in candidateProperties)
            {
                if (obj[property] is JArray arr)
                {
                    return arr;
                }
            }
        }

        return new JArray();
    }

    private static List<string> ExtractServiceTaxonomyTerms(JObject service, IReadOnlyDictionary<string, string> taxonomyById)
    {
        var taxonomyTokens = service["taxonomy_terms"] as JArray;
        var result = new List<string>();

        if (taxonomyTokens == null)
        {
            return result;
        }

        foreach (var token in taxonomyTokens)
        {
            if (token.Type == JTokenType.String)
            {
                var raw = token.ToString();
                if (taxonomyById.TryGetValue(raw, out var resolvedName))
                {
                    result.Add(resolvedName);
                }
                else
                {
                    result.Add(raw);
                }

                continue;
            }

            if (token is JObject termObj)
            {
                var name = termObj["name"]?.ToString();
                var id = termObj["id"]?.ToString();

                if (!string.IsNullOrWhiteSpace(name))
                {
                    result.Add(name);
                }
                else if (!string.IsNullOrWhiteSpace(id) && taxonomyById.TryGetValue(id, out var resolvedName))
                {
                    result.Add(resolvedName);
                }
            }
        }

        return result
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

}

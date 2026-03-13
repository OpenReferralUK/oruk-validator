using System.Net.Http.Headers;
using System.Net;
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
    private static readonly Regex EmailRegex = new("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex UrlRegex = new("^https?://", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex PlaceholderRegex = new("\\b(n/?a|none|unknown|test|tbd|placeholder|lorem ipsum)\\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex LetterRegex = new("[a-z]", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DigitRegex = new("\\d", RegexOptions.Compiled);

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
        var baseThreshold = request.MismatchThreshold ?? _options.MismatchThreshold;
        var threshold = request.StrictMode
            ? Math.Clamp(baseThreshold + _options.StrictModeThresholdAdjustment, 0, 1)
            : baseThreshold;
        var candidateTerms = BuildCandidateTerms(records, request);

        var findings = new List<SemanticAuditFinding>();
        foreach (var service in records)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var llmFinding = await ScoreWithLlmAsync(service, candidateTerms, threshold, cancellationToken);
            findings.Add(llmFinding ?? ScoreWithHeuristic(service, candidateTerms, threshold, request.StrictMode));
        }

        AddDuplicateIssues(records, findings, request.StrictMode);

        var engine = _semanticAuditAgentService.IsEnabled ? "microsoft-agent-framework" : "heuristic";

        var response = new SemanticDataAuditResponse
        {
            TotalServices = findings.Count,
            FlaggedServices = findings.Count(x => x.HasIssues),
            TotalIssues = findings.Sum(x => x.Issues.Count),
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

        var taxonomyById = await FetchTaxonomyTermsOptionalAsync(request, cancellationToken);
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
            var emails = ExtractEmailValues(service);
            var urls = ExtractUrlValues(service);
            var phoneNumbers = ExtractPhoneValues(service);
            var address = ExtractAddress(service);

            records.Add(new SemanticAuditServiceRecord
            {
                ServiceId = id,
                ServiceName = name,
                ServiceDescription = description,
                TaxonomyTerm = taxonomyTerms.FirstOrDefault() ?? "Unspecified",
                TaxonomyTerms = taxonomyTerms,
                Emails = emails,
                Urls = urls,
                PhoneNumbers = phoneNumbers,
                Address = address
            });
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
            var issues = evaluation.Issues
                .Where(x => x != null)
                .Select(issue => new FeedAuditIssue
                {
                    IssueType = issue.IssueType,
                    Severity = issue.Severity,
                    AffectedField = issue.AffectedField,
                    Description = issue.Description,
                    Suggestion = issue.Suggestion,
                    Confidence = Math.Clamp(issue.Confidence, 0, 1)
                })
                .Where(issue => issue.Confidence >= threshold)
                .ToList();

            return new SemanticAuditFinding
            {
                ServiceId = service.ServiceId,
                ServiceName = service.ServiceName,
                Issues = issues
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
        double threshold,
        bool strictMode)
    {
        var issues = BuildHeuristicIssues(service, candidateTerms, threshold, strictMode);

        return new SemanticAuditFinding
        {
            ServiceId = service.ServiceId,
            ServiceName = service.ServiceName,
            Issues = issues
        };
    }

    private List<FeedAuditIssue> BuildHeuristicIssues(
        SemanticAuditServiceRecord service,
        IReadOnlyCollection<string> candidateTerms,
        double threshold,
        bool strictMode)
    {
        var issues = new List<FeedAuditIssue>();

        var descriptionTokens = ExtractTokens(service.ServiceDescription);
        var nameTokens = ExtractTokens(service.ServiceName);
        var assignedTerm = string.IsNullOrWhiteSpace(service.TaxonomyTerm)
            ? service.TaxonomyTerms.FirstOrDefault() ?? "Unspecified"
            : service.TaxonomyTerm;
        var assignedTermScore = ScoreTerm(assignedTerm, descriptionTokens);

        var bestAlternative = candidateTerms
            .Where(t => !string.Equals(t, assignedTerm, StringComparison.OrdinalIgnoreCase))
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

        if (assignedLooksWeak && alternativeLooksBetter)
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "taxonomy_mismatch",
                Severity = "warning",
                AffectedField = "taxonomy_terms",
                Description = $"Assigned term '{assignedTerm}' appears weaker than '{bestAlternative?.Term}'.",
                Suggestion = $"Review taxonomy assignment and consider '{bestAlternative?.Term}'.",
                Confidence = Math.Clamp(bestAlternativeScore, 0, 1)
            });
        }
        else if (assignedLooksWeak && descriptionTokens.Count >= 8 && !string.Equals(assignedTerm, "Unspecified", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "data_inconsistency",
                Severity = "info",
                AffectedField = "taxonomy_terms",
                Description = $"Assigned term '{assignedTerm}' has weak evidence in the service description.",
                Suggestion = "Review taxonomy terms and add more concrete service details if the current term is correct.",
                Confidence = Math.Clamp(1 - assignedTermScore, 0.55, 0.9)
            });
        }

        if (_options.EnablePlaceholderChecks && ContainsPlaceholderValue(service.ServiceName))
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "inconsistent_name",
                Severity = "warning",
                AffectedField = "name",
                Description = "Service name looks like placeholder text.",
                Suggestion = "Replace placeholders with the real service name used by residents.",
                Confidence = 0.9
            });
        }

        if (_options.EnablePlaceholderChecks && ContainsPlaceholderValue(service.ServiceDescription))
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "poor_description",
                Severity = "warning",
                AffectedField = "description",
                Description = "Service description looks like placeholder text.",
                Suggestion = "Provide a clear summary of support offered, eligibility and how to access the service.",
                Confidence = 0.92
            });
        }

        if (_options.EnablePlaceholderChecks && ContainsPlaceholderValue(service.Address))
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "data_inconsistency",
                Severity = "info",
                AffectedField = "address",
                Description = "Address contains placeholder-like text.",
                Suggestion = "Replace temporary address content with a real location or remove it if unknown.",
                Confidence = 0.78
            });
        }

        var minDescriptionTokenCount = strictMode
            ? _options.MinDescriptionTokenCount + _options.StrictModeDescriptionTokenIncrease
            : _options.MinDescriptionTokenCount;

        if (descriptionTokens.Count < minDescriptionTokenCount)
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "poor_description",
                Severity = "warning",
                AffectedField = "description",
                Description = "Service description is very short and may be unclear for users.",
                Suggestion = "Add concrete details about eligibility, support offered, and how to access the service.",
                Confidence = 0.85
            });
        }

        if (nameTokens.Count >= 2 && descriptionTokens.Count >= 8 && assignedTermScore < threshold)
        {
            var overlap = nameTokens.Count(descriptionTokens.Contains);
            if (overlap == 0)
            {
                issues.Add(new FeedAuditIssue
                {
                    IssueType = "inconsistent_name",
                    Severity = "info",
                    AffectedField = "name",
                    Description = "Service name and description have no meaningful overlap, which may indicate mismatched data.",
                    Suggestion = "Check that the service name and description refer to the same offer.",
                    Confidence = 0.7
                });
            }
        }

        var validEmailCount = 0;
        foreach (var email in service.Emails)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                continue;
            }

            if (_options.EnableContactFieldContextChecks && UrlRegex.IsMatch(email))
            {
                issues.Add(new FeedAuditIssue
                {
                    IssueType = "invalid_data",
                    Severity = "warning",
                    AffectedField = "email",
                    Description = $"Email field contains a URL value '{email}'.",
                    Suggestion = "Move website URLs to a URL field and keep email in user@domain format.",
                    Confidence = 0.94
                });
                continue;
            }

            if (EmailRegex.IsMatch(email))
            {
                validEmailCount++;
                continue;
            }

            issues.Add(new FeedAuditIssue
            {
                IssueType = "invalid_data",
                Severity = "error",
                AffectedField = "email",
                Description = $"Email '{email}' does not look valid.",
                Suggestion = "Use a standard email format such as name@example.org.",
                Confidence = 0.98
            });
        }

        var validUrlCount = 0;
        foreach (var url in service.Urls)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                continue;
            }

            if (_options.EnableContactFieldContextChecks && EmailRegex.IsMatch(url))
            {
                issues.Add(new FeedAuditIssue
                {
                    IssueType = "invalid_data",
                    Severity = "warning",
                    AffectedField = "url",
                    Description = $"URL field contains an email value '{url}'.",
                    Suggestion = "Move email values to an email field and keep URLs in http(s) format.",
                    Confidence = 0.94
                });
                continue;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl)
                || !(parsedUrl.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                     || parsedUrl.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                || string.IsNullOrWhiteSpace(parsedUrl.Host)
                || !parsedUrl.Host.Contains('.'))
            {
                issues.Add(new FeedAuditIssue
                {
                    IssueType = "invalid_data",
                    Severity = "error",
                    AffectedField = "url",
                    Description = $"URL '{url}' is not a valid public http(s) URL.",
                    Suggestion = "Provide an absolute URL, for example https://example.org/service.",
                    Confidence = 0.98
                });
                continue;
            }

            validUrlCount++;
        }

        var validPhoneCount = 0;
        var minPhoneDigits = strictMode ? _options.PhoneMinDigits + 1 : _options.PhoneMinDigits;
        var maxPhoneDigits = strictMode ? _options.PhoneMaxDigits - 1 : _options.PhoneMaxDigits;
        if (maxPhoneDigits < minPhoneDigits)
        {
            maxPhoneDigits = minPhoneDigits;
        }

        foreach (var phone in service.PhoneNumbers)
        {
            if (string.IsNullOrWhiteSpace(phone))
            {
                continue;
            }

            var digitCount = DigitRegex.Matches(phone).Count;
            var containsLetters = LetterRegex.IsMatch(phone);
            var suspiciousRepeatedDigits = digitCount >= 7 && phone.Distinct().Count() <= 2;

            if (digitCount < minPhoneDigits || digitCount > maxPhoneDigits || containsLetters || suspiciousRepeatedDigits)
            {
                issues.Add(new FeedAuditIssue
                {
                    IssueType = "invalid_data",
                    Severity = "warning",
                    AffectedField = "phone",
                    Description = $"Phone number '{phone}' looks malformed.",
                    Suggestion = "Use a phone number with 7-15 digits and optional spacing or punctuation.",
                    Confidence = 0.86
                });
                continue;
            }

            validPhoneCount++;
        }

        if (validEmailCount + validPhoneCount + validUrlCount == 0)
        {
            issues.Add(new FeedAuditIssue
            {
                IssueType = "missing_contact",
                Severity = "warning",
                AffectedField = "contact",
                Description = "No contact email, phone number, or URL was found.",
                Suggestion = "Provide at least one contact channel so users can access the service.",
                Confidence = 0.95
            });
        }

        return issues;
    }

    private void AddDuplicateIssues(
        IReadOnlyList<SemanticAuditServiceRecord> records,
        IReadOnlyList<SemanticAuditFinding> findings,
        bool strictMode)
    {
        if (!_options.EnableDuplicateDetection || records.Count < 2 || findings.Count == 0)
        {
            return;
        }

        var duplicateThreshold = strictMode
            ? _options.DuplicateSimilarityThreshold - _options.StrictModeDuplicateThresholdReduction
            : _options.DuplicateSimilarityThreshold;
        var nearDuplicateThreshold = strictMode
            ? _options.NearDuplicateSimilarityThreshold - _options.StrictModeDuplicateThresholdReduction
            : _options.NearDuplicateSimilarityThreshold;

        duplicateThreshold = Math.Clamp(duplicateThreshold, 0, 1);
        nearDuplicateThreshold = Math.Clamp(nearDuplicateThreshold, 0, 1);

        if (nearDuplicateThreshold > duplicateThreshold)
        {
            nearDuplicateThreshold = duplicateThreshold;
        }

        var findingById = findings
            .GroupBy(x => x.ServiceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < records.Count; i++)
        {
            for (var j = i + 1; j < records.Count; j++)
            {
                var left = records[i];
                var right = records[j];

                if (string.Equals(left.ServiceId, right.ServiceId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var similarity = ComputeRecordSimilarity(left, right);
                if (similarity < nearDuplicateThreshold)
                {
                    continue;
                }

                var isLikelyDuplicate = similarity >= duplicateThreshold;
                var severity = isLikelyDuplicate ? "warning" : "info";
                var confidence = Math.Clamp(similarity, 0.6, 0.99);

                if (findingById.TryGetValue(left.ServiceId, out var leftFinding))
                {
                    AddDuplicateIssue(leftFinding, right, similarity, severity, confidence);
                }

                if (findingById.TryGetValue(right.ServiceId, out var rightFinding))
                {
                    AddDuplicateIssue(rightFinding, left, similarity, severity, confidence);
                }
            }
        }
    }

    private static void AddDuplicateIssue(
        SemanticAuditFinding finding,
        SemanticAuditServiceRecord other,
        double similarity,
        string severity,
        double confidence)
    {
        var duplicateKey = $"duplicate::{other.ServiceId}";
        if (finding.Issues.Any(x =>
                x.IssueType == "data_inconsistency"
                && string.Equals(x.AffectedField, duplicateKey, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        finding.Issues.Add(new FeedAuditIssue
        {
            IssueType = "data_inconsistency",
            Severity = severity,
            AffectedField = duplicateKey,
            Description = $"Potential duplicate of service '{other.ServiceId}' (similarity {similarity:F2}).",
            Suggestion = "Review these records for duplication and merge or differentiate where appropriate.",
            Confidence = confidence
        });
    }

    private static double ComputeRecordSimilarity(SemanticAuditServiceRecord left, SemanticAuditServiceRecord right)
    {
        var leftDescriptionTokens = NormalizeTokens(ExtractTokens(left.ServiceDescription));
        var rightDescriptionTokens = NormalizeTokens(ExtractTokens(right.ServiceDescription));
        var descriptionScore = JaccardSimilarity(leftDescriptionTokens, rightDescriptionTokens);

        var leftNameTokens = NormalizeTokens(ExtractTokens(left.ServiceName));
        var rightNameTokens = NormalizeTokens(ExtractTokens(right.ServiceName));
        var nameScore = JaccardSimilarity(leftNameTokens, rightNameTokens);

        var leftAddressTokens = NormalizeTokens(ExtractTokens(left.Address));
        var rightAddressTokens = NormalizeTokens(ExtractTokens(right.Address));
        var addressScore = JaccardSimilarity(leftAddressTokens, rightAddressTokens);

        var score = (descriptionScore * 0.7) + (nameScore * 0.2) + (addressScore * 0.1);

        if (!string.IsNullOrWhiteSpace(left.ServiceName)
            && string.Equals(NormalizeText(left.ServiceName), NormalizeText(right.ServiceName), StringComparison.OrdinalIgnoreCase))
        {
            score += 0.05;
        }

        if (!string.IsNullOrWhiteSpace(left.ServiceDescription)
            && string.Equals(NormalizeText(left.ServiceDescription), NormalizeText(right.ServiceDescription), StringComparison.OrdinalIgnoreCase))
        {
            score = Math.Max(score, 0.98);
        }

        return Math.Clamp(score, 0, 1);
    }

    private static double JaccardSimilarity(HashSet<string> left, HashSet<string> right)
    {
        if (left.Count == 0 || right.Count == 0)
        {
            return 0;
        }

        var intersectionCount = left.Count(right.Contains);
        var unionCount = left.Count + right.Count - intersectionCount;
        if (unionCount == 0)
        {
            return 0;
        }

        return (double)intersectionCount / unionCount;
    }

    private static string NormalizeText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return string.Join(' ', ExtractTokens(value));
    }

    private static bool ContainsPlaceholderValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return PlaceholderRegex.IsMatch(value);
    }

    private static IReadOnlyCollection<string> BuildCandidateTerms(
        IReadOnlyCollection<SemanticAuditServiceRecord> records,
        SemanticDataAuditRequest request)
    {
        var terms = records
            .SelectMany(x => x.TaxonomyTerms.Count > 0 ? x.TaxonomyTerms : [x.TaxonomyTerm])
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

    private async Task<Dictionary<string, string>> FetchTaxonomyTermsOptionalAsync(
        SemanticDataAuditRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            return await FetchTaxonomyTermsAsync(request, cancellationToken);
        }
        catch (HttpRequestException ex) when (
            ex.StatusCode == HttpStatusCode.NotFound
            || ex.StatusCode == HttpStatusCode.MethodNotAllowed
            || ex.StatusCode == HttpStatusCode.Forbidden)
        {
            _logger.LogWarning(
                ex,
                "Taxonomy terms endpoint '{TaxonomyPath}' is unavailable (status: {StatusCode}). Continuing semantic audit without taxonomy lookup.",
                request.TaxonomyTermsPath,
                ex.StatusCode);

            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
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

                // Set User-Agent
        httpRequest.Headers.Add("User-Agent", "JsonValidator/1.0.0");

        // Set Accept headers for better compatibility
        httpRequest.Headers.Add("Accept", "application/json, application/schema+json, text/plain, */*");

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

    private static List<string> ExtractEmailValues(JObject service)
    {
        return ExtractStringValues(service, "email", "organization.email", "contact.email");
    }

    private static List<string> ExtractUrlValues(JObject service)
    {
        return ExtractStringValues(service, "url", "website", "organization.website", "organization.url", "organization.uri");
    }

    private static List<string> ExtractPhoneValues(JObject service)
    {
        var values = new List<string>();
        values.AddRange(ExtractStringValues(service, "phone", "telephone", "organization.phone"));

        if (service["phones"] is JArray phonesArray)
        {
            foreach (var item in phonesArray)
            {
                if (item is JValue scalar)
                {
                    var phone = scalar.ToString();
                    if (!string.IsNullOrWhiteSpace(phone))
                    {
                        values.Add(phone);
                    }
                }
                else if (item is JObject phoneObj)
                {
                    var number = phoneObj["number"]?.ToString() ?? phoneObj["phone"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(number))
                    {
                        values.Add(number);
                    }
                }
            }
        }

        return values
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? ExtractAddress(JObject service)
    {
        var addressParts = new[]
        {
            service["address_1"]?.ToString(),
            service["address_2"]?.ToString(),
            service["city"]?.ToString(),
            service["region"]?.ToString(),
            service["postal_code"]?.ToString(),
            service["location"]?["address_1"]?.ToString(),
            service["location"]?["city"]?.ToString(),
            service["location"]?["postal_code"]?.ToString()
        }
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .ToList();

        if (addressParts.Count == 0)
        {
            return null;
        }

        return string.Join(", ", addressParts);
    }

    private static List<string> ExtractStringValues(JObject service, params string[] paths)
    {
        var result = new List<string>();

        foreach (var path in paths)
        {
            var token = service.SelectToken(path);
            if (token == null)
            {
                continue;
            }

            if (token is JValue value)
            {
                var text = value.ToString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    result.Add(text);
                }
            }
            else if (token is JArray array)
            {
                foreach (var item in array)
                {
                    var text = item?.ToString();
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        result.Add(text);
                    }
                }
            }
        }

        return result
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

}

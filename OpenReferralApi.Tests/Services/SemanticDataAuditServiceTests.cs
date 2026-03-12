using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Newtonsoft.Json.Linq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class SemanticDataAuditServiceTests
{
    [Test]
    public async Task AuditAsync_FlagsFoodBankTaggedAsLegalAid()
    {
        var service = CreateService(
            new StubHttpMessageHandler(_ => throw new InvalidOperationException("HTTP should not be called for direct service list mode.")),
            new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)));

        var request = new SemanticDataAuditRequest
        {
            TaxonomyTerms = new List<string> { "Food Bank", "Legal Aid" },
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-1",
                    ServiceName = "Community Pantry",
                    ServiceDescription = "Provides emergency food parcels, groceries and hot meals to local families.",
                    TaxonomyTerm = "Legal Aid"
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.TotalServices, Is.EqualTo(1));
        Assert.That(result.FlaggedServices, Is.EqualTo(1));
        Assert.That(result.Findings, Has.Count.EqualTo(1));
        Assert.That(result.Findings[0].Issues, Has.Count.GreaterThan(0));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "taxonomy_mismatch"), Is.True);
    }

    [Test]
    public async Task AuditAsync_DoesNotFlagMatchingLegalAidService()
    {
        var service = CreateService(
            new StubHttpMessageHandler(_ => throw new InvalidOperationException("HTTP should not be called for direct service list mode.")),
            new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)));

        var request = new SemanticDataAuditRequest
        {
            TaxonomyTerms = new List<string> { "Food Bank", "Legal Aid" },
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-2",
                    ServiceName = "Tenant Rights Clinic",
                    ServiceDescription = "Free legal advice about housing law, eviction notices and tribunal representation.",
                    TaxonomyTerm = "Legal Aid",
                    Emails = new List<string> { "contact@example.org" },
                    Urls = new List<string> { "https://example.org/tenant-rights" }
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.TotalServices, Is.EqualTo(1));
        Assert.That(result.FlaggedServices, Is.EqualTo(0));
        Assert.That(result.Findings[0].Issues, Is.Empty);
    }

    [Test]
    public async Task AuditAsync_WithSourceBaseUrl_UsesLlmWithoutPostingServiceList()
    {
        var service = CreateService(new StubHttpMessageHandler(request =>
        {
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath.EndsWith("/services", StringComparison.Ordinal))
            {
                var payload = new JObject
                {
                    ["services"] = new JArray
                    {
                        new JObject
                        {
                            ["id"] = "svc-1",
                            ["name"] = "Community Pantry",
                            ["description"] = "Provides emergency food parcels and groceries.",
                            ["taxonomy_terms"] = new JArray("legal-aid")
                        }
                    }
                };

                return Json(payload);
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath.EndsWith("/taxonomy_terms", StringComparison.Ordinal))
            {
                var payload = new JObject
                {
                    ["taxonomy_terms"] = new JArray
                    {
                        new JObject
                        {
                            ["id"] = "legal-aid",
                            ["name"] = "Legal Aid"
                        },
                        new JObject
                        {
                            ["id"] = "food-bank",
                            ["name"] = "Food Bank"
                        }
                    }
                };

                return Json(payload);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }),
        new StubSemanticAuditAgentService(
            true,
            (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(new SemanticAuditAgentEvaluation
            {
                Issues = new List<FeedAuditIssue>
                {
                    new()
                    {
                        IssueType = "taxonomy_mismatch",
                        Severity = "warning",
                        AffectedField = "taxonomy_terms",
                        Description = "Description indicates food support, not legal services.",
                        Suggestion = "Use Food Bank taxonomy term.",
                        Confidence = 0.92
                    }
                }
            })));

        var request = new SemanticDataAuditRequest
        {
            SourceBaseUrl = "https://example-directory.test"
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.TotalServices, Is.EqualTo(1));
        Assert.That(result.FlaggedServices, Is.EqualTo(1));
        Assert.That(result.AuditEngine, Is.EqualTo("microsoft-agent-framework"));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "taxonomy_mismatch"), Is.True);
    }

    [Test]
    public async Task AuditAsync_FlagsMissingContactAndInvalidEmail()
    {
        var service = CreateService(
            new StubHttpMessageHandler(_ => throw new InvalidOperationException("HTTP should not be called for direct service list mode.")),
            new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)));

        var request = new SemanticDataAuditRequest
        {
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-3",
                    ServiceName = "Local Support Hub",
                    ServiceDescription = "Help",
                    TaxonomyTerm = "Housing Advice",
                    Emails = new List<string> { "not-an-email" }
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.FlaggedServices, Is.EqualTo(1));
        Assert.That(result.TotalIssues, Is.GreaterThanOrEqualTo(2));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "invalid_data" && x.AffectedField == "email"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "poor_description"), Is.True);
    }

    private static SemanticDataAuditService CreateService(HttpMessageHandler handler, ISemanticAuditAgentService agentService)
    {
        var options = Options.Create(new SemanticDataAuditOptions
        {
            Enabled = true,
            MismatchThreshold = 0.4,
            MinimumAlternativeGap = 0.25
        });

        var authOptions = Options.Create(new AuthenticationOptions
        {
            AllowUserSuppliedAuth = true
        });

        var logger = new Mock<ILogger<SemanticDataAuditService>>();
        var httpClient = new HttpClient(handler);

        return new SemanticDataAuditService(options, agentService, authOptions, httpClient, logger.Object);
    }

    private static HttpResponseMessage Json(JObject payload)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(payload.ToString(), Encoding.UTF8, "application/json")
        };
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }

    private sealed class StubSemanticAuditAgentService : ISemanticAuditAgentService
    {
        private readonly Func<SemanticAuditServiceRecord, IReadOnlyCollection<string>, CancellationToken, Task<SemanticAuditAgentEvaluation?>> _handler;

        public StubSemanticAuditAgentService(
            bool isEnabled,
            Func<SemanticAuditServiceRecord, IReadOnlyCollection<string>, CancellationToken, Task<SemanticAuditAgentEvaluation?>> handler)
        {
            IsEnabled = isEnabled;
            _handler = handler;
        }

        public bool IsEnabled { get; }

        public Task<SemanticAuditAgentEvaluation?> EvaluateAsync(
            SemanticAuditServiceRecord service,
            IReadOnlyCollection<string> candidateTerms,
            CancellationToken cancellationToken = default)
        {
            return _handler(service, candidateTerms, cancellationToken);
        }
    }
}

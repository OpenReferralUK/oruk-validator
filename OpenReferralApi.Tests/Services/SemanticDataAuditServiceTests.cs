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
    public async Task AuditAsync_WithSourceBaseUrl_AllowsMissingTaxonomyEndpoint()
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
                            ["id"] = "svc-no-taxonomy",
                            ["name"] = "Tenant Rights Clinic",
                            ["description"] = "Free legal advice about housing law, eviction notices and tribunal representation.",
                            ["taxonomy_terms"] = new JArray("legal-aid"),
                            ["email"] = "contact@example.org",
                            ["url"] = "https://example.org/tenant-rights"
                        }
                    }
                };

                return Json(payload);
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath.EndsWith("/taxonomy_terms", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }),
        new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)));

        var request = new SemanticDataAuditRequest
        {
            SourceBaseUrl = "https://example-directory.test"
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.TotalServices, Is.EqualTo(1));
        Assert.That(result.Findings[0].ServiceId, Is.EqualTo("svc-no-taxonomy"));
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

    [Test]
    public async Task AuditAsync_FlagsOutOfContextContactAndPlaceholderValues()
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
                    ServiceId = "svc-4",
                    ServiceName = "Test Service",
                    ServiceDescription = "N/A",
                    TaxonomyTerm = "Housing Advice",
                    Emails = new List<string> { "https://example.org/contact" },
                    Urls = new List<string> { "support@example.org" },
                    PhoneNumbers = new List<string> { "abc123" },
                    Address = "unknown"
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.FlaggedServices, Is.EqualTo(1));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "inconsistent_name" && x.AffectedField == "name"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "poor_description" && x.AffectedField == "description"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "invalid_data" && x.AffectedField == "email"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "invalid_data" && x.AffectedField == "url"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "invalid_data" && x.AffectedField == "phone"), Is.True);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "missing_contact"), Is.True);
    }

    [Test]
    public async Task AuditAsync_StrictMode_FlagsBorderlineDescription()
    {
        var service = CreateService(
            new StubHttpMessageHandler(_ => throw new InvalidOperationException("HTTP should not be called for direct service list mode.")),
            new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)));

        var request = new SemanticDataAuditRequest
        {
            StrictMode = true,
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-5",
                    ServiceName = "Tenant Advice Hub",
                    ServiceDescription = "Legal advice for housing eviction rights appeals",
                    TaxonomyTerm = "Legal Aid",
                    Emails = new List<string> { "help@example.org" },
                    Urls = new List<string> { "https://example.org/help" }
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.FlaggedServices, Is.EqualTo(1));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "poor_description"), Is.True);
    }

    [Test]
    public async Task AuditAsync_FlagsDuplicateServicesAcrossFeed()
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
                    ServiceId = "svc-6",
                    ServiceName = "Family Food Hub",
                    ServiceDescription = "Emergency food parcels and grocery support for local families in crisis.",
                    TaxonomyTerm = "Food Bank",
                    Emails = new List<string> { "food@example.org" }
                },
                new()
                {
                    ServiceId = "svc-7",
                    ServiceName = "Family Food Hub",
                    ServiceDescription = "Emergency food parcels and grocery support for local families in crisis.",
                    TaxonomyTerm = "Food Bank",
                    Emails = new List<string> { "food@example.org" }
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.FlaggedServices, Is.EqualTo(2));
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "data_inconsistency" && x.AffectedField == "duplicate::svc-7"), Is.True);
        Assert.That(result.Findings[1].Issues.Any(x => x.IssueType == "data_inconsistency" && x.AffectedField == "duplicate::svc-6"), Is.True);
    }

    [Test]
    public async Task AuditAsync_DisablesPlaceholderChecks_WhenConfigured()
    {
        var service = CreateService(
            new StubHttpMessageHandler(_ => throw new InvalidOperationException("HTTP should not be called for direct service list mode.")),
            new StubSemanticAuditAgentService(false, (_, _, _) => Task.FromResult<SemanticAuditAgentEvaluation?>(null)),
            new SemanticDataAuditOptions
            {
                Enabled = true,
                MismatchThreshold = 0.4,
                MinimumAlternativeGap = 0.25,
                EnablePlaceholderChecks = false
            });

        var request = new SemanticDataAuditRequest
        {
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-8",
                    ServiceName = "Test",
                    ServiceDescription = "Placeholder text with enough detail to pass description length checks for this scenario.",
                    TaxonomyTerm = "Housing Advice",
                    Emails = new List<string> { "help@example.org" },
                    Urls = new List<string> { "https://example.org/help" }
                }
            }
        };

        var result = await service.AuditAsync(request);

        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "inconsistent_name" && x.AffectedField == "name"), Is.False);
        Assert.That(result.Findings[0].Issues.Any(x => x.IssueType == "poor_description" && x.AffectedField == "description"), Is.False);
    }

    private static SemanticDataAuditService CreateService(
        HttpMessageHandler handler,
        ISemanticAuditAgentService agentService,
        SemanticDataAuditOptions? semanticOptions = null)
    {
        var options = Options.Create(semanticOptions ?? new SemanticDataAuditOptions
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

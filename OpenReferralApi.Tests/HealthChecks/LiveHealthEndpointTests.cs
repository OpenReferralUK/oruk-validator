using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace OpenReferralApi.Tests.HealthChecks;

[TestFixture]
public class LiveHealthEndpointTests
{
    [Test]
    public async Task LiveHealthEndpoint_IncludesSchemaWarmupPayload()
    {
        await using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["SchemaWarmup:Enabled"] = "false",
                        ["FeedValidation:Enabled"] = "false"
                    });
                });
            });

        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health-check/live");
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        Assert.That(root.TryGetProperty("schemaWarmup", out var schemaWarmup), Is.True);
        var hasState = schemaWarmup.TryGetProperty("state", out var state) ||
                       schemaWarmup.TryGetProperty("State", out state);
        Assert.That(hasState, Is.True);
        Assert.That(state.GetString(), Is.Not.Null.And.Not.Empty);
    }
}

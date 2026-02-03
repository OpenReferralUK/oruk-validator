using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Core.Services;
using OpenReferralApi.HealthChecks;

namespace OpenReferralApi.Tests.HealthChecks;

[TestFixture]
public class FeedValidationHealthCheckTests
{
    [Test]
    public async Task CheckHealthAsync_WhenFeedValidationDisabled_ReturnsHealthy()
    {
        // Arrange
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["FeedValidation:Enabled"] = "false"
        });
        var feedValidationService = new Mock<IFeedValidationService>();
        var healthCheck = new FeedValidationHealthCheck(configuration, feedValidationService.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Be("Feed validation is disabled");
    }

    [Test]
    public async Task CheckHealthAsync_WhenFeedValidationEnabledAndNullService_ReturnsDegraded()
    {
        // Arrange
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["FeedValidation:Enabled"] = "true"
        });
        var loggerMock = new Mock<ILogger<NullFeedValidationService>>();
        var feedValidationService = new NullFeedValidationService(loggerMock.Object);
        var healthCheck = new FeedValidationHealthCheck(configuration, feedValidationService);

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Be("Feed validation service is not configured");
    }

    [Test]
    public async Task CheckHealthAsync_WhenFeedValidationEnabledAndServiceConfigured_ReturnsHealthy()
    {
        // Arrange
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["FeedValidation:Enabled"] = "true"
        });
        var feedValidationService = new Mock<IFeedValidationService>();
        var healthCheck = new FeedValidationHealthCheck(configuration, feedValidationService.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Be("Feed validation service is configured");
    }

    [Test]
    public async Task CheckHealthAsync_WhenSettingMissing_DefaultsToDisabled()
    {
        // Arrange
        var configuration = BuildConfiguration(new Dictionary<string, string?>());
        var feedValidationService = new Mock<IFeedValidationService>();
        var healthCheck = new FeedValidationHealthCheck(configuration, feedValidationService.Object);

        // Act
        var result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Be("Feed validation is disabled");
    }

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> settings)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();
    }
}

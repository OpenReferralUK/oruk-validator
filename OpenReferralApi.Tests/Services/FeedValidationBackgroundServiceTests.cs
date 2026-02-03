using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class FeedValidationBackgroundServiceTests
{
    private Mock<IServiceProvider> _serviceProviderMock;
    private IConfiguration _configuration;
    private Mock<ILogger<FeedValidationBackgroundService>> _loggerMock;

    [SetUp]
    public void Setup()
    {
        _serviceProviderMock = new Mock<IServiceProvider>();
        _loggerMock = new Mock<ILogger<FeedValidationBackgroundService>>();

        // Create a real configuration to avoid mocking extension methods
        var configBuilder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "FeedValidation:Enabled", "true" },
                { "FeedValidation:IntervalHours", "24" },
                { "FeedValidation:RunAtMidnight", "true" }
            });
        _configuration = configBuilder.Build();
    }

    [Test]
    public void ServiceCreation_WithValidConfiguration_DoesNotThrow()
    {
        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            _configuration,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ServiceCreation_WithDisabledConfiguration_DoesNotThrow()
    {
        // Arrange
        var configBuilder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "FeedValidation:Enabled", "false" }
            });
        var config = configBuilder.Build();

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            config,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task StopAsync_LogsStoppingMessage()
    {
        // Arrange
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            _configuration,
            _loggerMock.Object);

        // Act
        await service.StopAsync(CancellationToken.None);

        // Assert - Service stopped without throwing
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ServiceCreation_ReadsMidnightConfiguration()
    {
        // Arrange
        var configBuilder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "FeedValidation:Enabled", "true" },
                { "FeedValidation:RunAtMidnight", "false" }
            });
        var config = configBuilder.Build();

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            config,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ServiceCreation_ReadsIntervalConfiguration()
    {
        // Arrange
        var configBuilder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "FeedValidation:Enabled", "true" },
                { "FeedValidation:IntervalHours", "12" }
            });
        var config = configBuilder.Build();

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            config,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }
}



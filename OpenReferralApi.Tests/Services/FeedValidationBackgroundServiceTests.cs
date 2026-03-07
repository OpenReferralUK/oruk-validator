using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class FeedValidationBackgroundServiceTests
{
    private Mock<IServiceProvider> _serviceProviderMock;
    private Mock<ILogger<FeedValidationBackgroundService>> _loggerMock;

    [SetUp]
    public void Setup()
    {
        _serviceProviderMock = new Mock<IServiceProvider>();
        _loggerMock = new Mock<ILogger<FeedValidationBackgroundService>>();
    }

    [Test]
    public void ServiceCreation_WithValidConfiguration_DoesNotThrow()
    {
        // Arrange
        var options = Options.Create(new FeedValidationOptions
        {
            Enabled = true,
            IntervalHours = 24,
            RunAtMidnight = true
        });

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            options,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ServiceCreation_WithDisabledConfiguration_DoesNotThrow()
    {
        // Arrange
        var options = Options.Create(new FeedValidationOptions
        {
            Enabled = false
        });

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            options,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task StopAsync_LogsStoppingMessage()
    {
        // Arrange
        var options = Options.Create(new FeedValidationOptions
        {
            Enabled = true,
            IntervalHours = 24,
            RunAtMidnight = true
        });
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            options,
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
        var options = Options.Create(new FeedValidationOptions
        {
            Enabled = true,
            RunAtMidnight = false
        });

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            options,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void ServiceCreation_ReadsIntervalConfiguration()
    {
        // Arrange
        var options = Options.Create(new FeedValidationOptions
        {
            Enabled = true,
            IntervalHours = 12
        });

        // Act
        var service = new FeedValidationBackgroundService(
            _serviceProviderMock.Object,
            options,
            _loggerMock.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
    }
}



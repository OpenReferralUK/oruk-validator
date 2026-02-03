using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Controllers;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Controllers;

[TestFixture]
public class FeedValidationControllerTests
{
    private Mock<IFeedValidationService> _feedValidationServiceMock;
    private Mock<ILogger<FeedValidationController>> _loggerMock;
    private FeedValidationController _controller;

    [SetUp]
    public void Setup()
    {
        _feedValidationServiceMock = new Mock<IFeedValidationService>();
        _loggerMock = new Mock<ILogger<FeedValidationController>>();

        _controller = new FeedValidationController(
            _feedValidationServiceMock.Object,
            _loggerMock.Object);
    }

    [Test]
    public async Task GetAllFeeds_ReturnsOkWithFeeds()
    {
        // Arrange
        var feeds = new List<ServiceFeed>
        {
            new ServiceFeed { Id = "1", UrlField = "https://example1.com" },
            new ServiceFeed { Id = "2", UrlField = "https://example2.com" }
        };

        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(feeds);

        // Act
        var result = await _controller.GetAllFeeds(CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        var okResult = result.Result as OkObjectResult;
        var returnedFeeds = okResult?.Value as List<ServiceFeed>;
        Assert.That(returnedFeeds, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task GetAllFeeds_WithException_ReturnsInternalServerError()
    {
        // Arrange
        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _controller.GetAllFeeds(CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<ObjectResult>());
        var objectResult = result.Result as ObjectResult;
        Assert.That(objectResult?.StatusCode, Is.EqualTo(500));
    }

    [Test]
    public async Task ValidateAllFeeds_WithFeeds_ReturnsValidationSummary()
    {
        // Arrange
        var feeds = new List<ServiceFeed>
        {
            new ServiceFeed { Id = "1", UrlField = "https://example1.com", ActiveField = true },
            new ServiceFeed { Id = "2", UrlField = "https://example2.com", ActiveField = true }
        };

        var validationResults = new List<FeedValidationResult>
        {
            new FeedValidationResult { FeedId = "1", IsUp = true, IsValid = true, ResponseTimeMs = 100 },
            new FeedValidationResult { FeedId = "2", IsUp = true, IsValid = false, ResponseTimeMs = 150 }
        };

        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(feeds);

        _feedValidationServiceMock
            .Setup(x => x.ValidateSingleFeedAsync(It.IsAny<ServiceFeed>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((ServiceFeed f, CancellationToken ct) =>
                validationResults.First(r => r.FeedId == f.Id));

        _feedValidationServiceMock
            .Setup(x => x.UpdateFeedStatusAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<double?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.ValidateAllFeeds(CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        var okResult = result.Result as OkObjectResult;
        var summary = okResult?.Value as FeedValidationSummary;
        Assert.That(summary?.TotalFeeds, Is.EqualTo(2));
        Assert.That(summary?.UpFeeds, Is.EqualTo(2));
        Assert.That(summary?.ValidFeeds, Is.EqualTo(1));
        Assert.That(summary?.InvalidFeeds, Is.EqualTo(1));
    }

    [Test]
    public async Task ValidateAllFeeds_WithNoFeeds_ReturnsEmptySummary()
    {
        // Arrange
        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ServiceFeed>());

        // Act
        var result = await _controller.ValidateAllFeeds(CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        var okResult = result.Result as OkObjectResult;
        var summary = okResult?.Value as FeedValidationSummary;
        Assert.That(summary?.TotalFeeds, Is.EqualTo(0));
        Assert.That(summary?.Message, Does.Contain("No feeds found"));
    }

    [Test]
    public async Task ValidateAllFeeds_WithException_ReturnsInternalServerError()
    {
        // Arrange
        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Validation error"));

        // Act
        var result = await _controller.ValidateAllFeeds(CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<ObjectResult>());
        var objectResult = result.Result as ObjectResult;
        Assert.That(objectResult?.StatusCode, Is.EqualTo(500));
    }

    [Test]
    public async Task ValidateFeed_WithExistingFeed_ReturnsValidationResult()
    {
        // Arrange
        var feedId = "1";
        var feed = new ServiceFeed { Id = feedId, UrlField = "https://example.com" };
        var validationResult = new FeedValidationResult
        {
            FeedId = feedId,
            IsUp = true,
            IsValid = true,
            ResponseTimeMs = 100
        };

        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ServiceFeed> { feed });

        _feedValidationServiceMock
            .Setup(x => x.ValidateSingleFeedAsync(feed, It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        _feedValidationServiceMock
            .Setup(x => x.UpdateFeedStatusAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<double?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.ValidateFeed(feedId, CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        var okResult = result.Result as OkObjectResult;
        var returnedResult = okResult?.Value as FeedValidationResult;
        Assert.That(returnedResult?.FeedId, Is.EqualTo(feedId));
        Assert.That(returnedResult?.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateFeed_WithNonexistentFeed_ReturnsNotFound()
    {
        // Arrange
        var feedId = "nonexistent";
        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ServiceFeed>());

        // Act
        var result = await _controller.ValidateFeed(feedId, CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<NotFoundObjectResult>());
    }

    [Test]
    public async Task ValidateFeed_WithException_ReturnsInternalServerError()
    {
        // Arrange
        var feedId = "1";
        _feedValidationServiceMock
            .Setup(x => x.GetAllFeedsAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Validation error"));

        // Act
        var result = await _controller.ValidateFeed(feedId, CancellationToken.None);

        // Assert
        Assert.That(result.Result, Is.TypeOf<ObjectResult>());
        var objectResult = result.Result as ObjectResult;
        Assert.That(objectResult?.StatusCode, Is.EqualTo(500));
    }
}


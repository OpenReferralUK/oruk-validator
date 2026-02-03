using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class FeedValidationServiceTests
{
    private Mock<IOpenApiValidationService> _validationServiceMock;
    private Mock<ILogger<FeedValidationService>> _loggerMock;
    private IConfiguration _configuration;

    [SetUp]
    public void Setup()
    {
        _validationServiceMock = new Mock<IOpenApiValidationService>();
        _loggerMock = new Mock<ILogger<FeedValidationService>>();

        // Create a real configuration to avoid mocking extension methods
        var configBuilder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Database:DatabaseName", "test-db" }
            });
        _configuration = configBuilder.Build();
    }

    private FeedValidationService CreateService()
    {
        var mongoClientMock = new Mock<IMongoClient>();
        var mongoDatabaseMock = new Mock<IMongoDatabase>();
        var collectionMock = new Mock<IMongoCollection<ServiceFeed>>();

        mongoClientMock
            .Setup(x => x.GetDatabase("test-db", null))
            .Returns(mongoDatabaseMock.Object);

        mongoDatabaseMock
            .Setup(x => x.GetCollection<ServiceFeed>("services", null))
            .Returns(collectionMock.Object);

        return new FeedValidationService(
            mongoClientMock.Object,
            _configuration,
            _validationServiceMock.Object,
            _loggerMock.Object);
    }

    [Test]
    public async Task ValidateSingleFeedAsync_WithValidFeed_ReturnsSuccessResult()
    {
        // Arrange
        var service = CreateService();
        var feed = new ServiceFeed { Id = "1", UrlField = "https://example.com", Service = null };

        var validationResult = new OpenApiValidationResult
        {
            IsValid = true,
            Duration = TimeSpan.FromSeconds(2),
            SpecificationValidation = new OpenApiSpecificationValidation { Errors = new List<ValidationError>() }
        };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        // Act
        var result = await service.ValidateSingleFeedAsync(feed);

        // Assert
        Assert.That(result.IsUp, Is.True);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.FeedId, Is.EqualTo("1"));
        Assert.That(result.ErrorMessage, Is.Null.Or.Empty);
        Assert.That(result.ResponseTimeMs, Is.GreaterThan(1900).And.LessThan(2100));
    }

    [Test]
    public async Task ValidateSingleFeedAsync_WithInvalidFeed_ReturnsInvalidResult()
    {
        // Arrange
        var service = CreateService();
        var feed = new ServiceFeed { Id = "1", UrlField = "https://example.com" };

        var validationResult = new OpenApiValidationResult
        {
            IsValid = false,
            Duration = TimeSpan.FromSeconds(1),
            SpecificationValidation = new OpenApiSpecificationValidation
            {
                Errors = new List<ValidationError>
                {
                    new ValidationError { Path = "/paths", Message = "Invalid path" },
                    new ValidationError { Path = "/definitions", Message = "Invalid schema" }
                }
            }
        };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        // Act
        var result = await service.ValidateSingleFeedAsync(feed);

        // Assert
        Assert.That(result.IsUp, Is.True);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidationErrorCount, Is.EqualTo(2));
        Assert.That(result.ErrorMessage, Does.Contain("Invalid path"));
    }

    [Test]
    public async Task ValidateSingleFeedAsync_WithHttpError_ReturnsDownFeed()
    {
        // Arrange
        var service = CreateService();
        var feed = new ServiceFeed { Id = "1", UrlField = "https://invalid.example.com" };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Connection timeout"));

        // Act
        var result = await service.ValidateSingleFeedAsync(feed);

        // Assert
        Assert.That(result.IsUp, Is.False);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ErrorMessage, Does.Contain("HTTP error"));
    }

    [Test]
    public async Task ValidateSingleFeedAsync_WithTimeout_ReturnsDownFeed()
    {
        // Arrange
        var service = CreateService();
        var feed = new ServiceFeed { Id = "1", UrlField = "https://slow.example.com" };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("Request timed out"));

        // Act
        var result = await service.ValidateSingleFeedAsync(feed);

        // Assert
        Assert.That(result.IsUp, Is.False);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ErrorMessage, Does.Contain("timed out"));
    }
}
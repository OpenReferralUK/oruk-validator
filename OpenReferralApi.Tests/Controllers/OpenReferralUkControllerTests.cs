using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Controllers;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Controllers;

[TestFixture]
public class OpenReferralUkControllerTests
{
    private Mock<IOpenApiValidationService> _validationServiceMock;
    private Mock<ILogger<OpenReferralUkController>> _loggerMock;
    private Mock<IOpenReferralUKValidationResponseMapper> _mapperMock;
    private OpenReferralUkController _controller;

    [SetUp]
    public void Setup()
    {
        _validationServiceMock = new Mock<IOpenApiValidationService>();
        _loggerMock = new Mock<ILogger<OpenReferralUkController>>();
        _mapperMock = new Mock<IOpenReferralUKValidationResponseMapper>();

        _controller = new OpenReferralUkController(
            _validationServiceMock.Object,
            _loggerMock.Object,
            _mapperMock.Object);
    }

    [Test]
    public async Task ValidateAsync_WhenMappedResponseContainsNotifications_ReturnsNotifications()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            BaseUrl = "https://api.example.com",
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://api.example.com/openapi.json"
            }
        };

        var validationResult = new OpenApiValidationResult
        {
            IsValid = false,
            Notifications = new List<string>
            {
                "Unable to get or resolve the OpenAPI specification from https://api.example.com/openapi.json. 404"
            }
        };

        var mappedResult = new OpenReferralUKValidationResponse
        {
            Service = new ServiceInfo
            {
                Url = "https://api.example.com",
                IsValid = false,
                Profile = "Unknown",
                ProfileReason = "Unknown"
            },
            Notifications = new List<string>
            {
                "Unable to get or resolve the OpenAPI specification from https://api.example.com/openapi.json. 404"
            }
        };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        _mapperMock
            .Setup(x => x.MapToOpenReferralUKValidationResponse(validationResult))
            .Returns(mappedResult);

        // Act
        var actionResult = await _controller.ValidateAsync(request);

        // Assert
        Assert.That(actionResult.Result, Is.TypeOf<OkObjectResult>());
        var ok = (OkObjectResult)actionResult.Result!;
        Assert.That(ok.Value, Is.TypeOf<OpenReferralUKValidationResponse>());

        var response = (OpenReferralUKValidationResponse)ok.Value!;
        Assert.That(response.Notifications, Has.Count.EqualTo(1));
        Assert.That(response.Notifications[0], Does.Contain("Unable to get or resolve the OpenAPI specification"));

        _validationServiceMock.Verify(
            x => x.ValidateOpenApiSpecificationAsync(request, It.IsAny<CancellationToken>()),
            Times.Once);
        _mapperMock.Verify(x => x.MapToOpenReferralUKValidationResponse(validationResult), Times.Once);
    }
}
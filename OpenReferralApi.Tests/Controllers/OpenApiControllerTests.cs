using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Controllers;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Controllers;

[TestFixture]
public class OpenApiControllerTests
{
    private Mock<IOpenApiValidationService> _validationServiceMock;
    private Mock<ILogger<OpenApiController>> _loggerMock;
    private OpenApiController _controller;

    [SetUp]
    public void Setup()
    {
        _validationServiceMock = new Mock<IOpenApiValidationService>();
        _loggerMock = new Mock<ILogger<OpenApiController>>();

        _controller = new OpenApiController(
            _validationServiceMock.Object,
            _loggerMock.Object);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithValidRequest_ReturnsOkResult()
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
            IsValid = true
        };
        
        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        // Act
        var result = await _controller.ValidateAsync(request);

        // Assert
        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        _validationServiceMock.Verify(x => x.ValidateOpenApiSpecificationAsync(request, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithMissingBaseUrl_ReturnsBadRequest()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            BaseUrl = null,
            OpenApiSchema = null
        };

        // Act
        var result = await _controller.ValidateAsync(request);

        // Assert
        Assert.That(result.Result, Is.TypeOf<BadRequestObjectResult>());
    }
}

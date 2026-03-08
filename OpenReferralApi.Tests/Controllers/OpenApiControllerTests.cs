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
    private Mock<ILogger<OpenReferralController>> _loggerMock;
    private OpenReferralController _controller;

    [SetUp]
    public void Setup()
    {
        _validationServiceMock = new Mock<IOpenApiValidationService>();
        _loggerMock = new Mock<ILogger<OpenReferralController>>();

        _controller = new OpenReferralController(
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
    public async Task ValidateOpenApiSpecificationAsync_WhenValidationReturnsNotifications_IncludesNotificationsInResponse()
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

        var expectedNotification = "Unable to get or resolve the OpenAPI specification from https://api.example.com/openapi.json. 404";
        var validationResult = new OpenApiValidationResult
        {
            IsValid = false,
            Notifications = new List<string> { expectedNotification }
        };

        _validationServiceMock
            .Setup(x => x.ValidateOpenApiSpecificationAsync(It.IsAny<OpenApiValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        // Act
        var actionResult = await _controller.ValidateAsync(request);

        // Assert
        Assert.That(actionResult.Result, Is.TypeOf<OkObjectResult>());
        var ok = (OkObjectResult)actionResult.Result!;
        Assert.That(ok.Value, Is.TypeOf<OpenApiValidationResult>());

        var response = (OpenApiValidationResult)ok.Value!;
        Assert.That(response.Notifications, Has.Count.EqualTo(1));
        Assert.That(response.Notifications[0], Is.EqualTo(expectedNotification));
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

    [Test]
    public void OpenReferralController_UsesOpenReferralRoute()
    {
        // Regression guard: route should stay as openreferral for endpoint path consistency.
        var routeAttribute = typeof(OpenReferralController)
            .GetCustomAttributes(typeof(RouteAttribute), inherit: false)
            .Cast<RouteAttribute>()
            .SingleOrDefault();

        Assert.That(routeAttribute, Is.Not.Null);
        Assert.That(routeAttribute!.Template, Is.EqualTo("openreferral"));
    }

    [Test]
    public void OpenReferralController_NameProducesOpenReferralSwaggerTag()
    {
        // Swashbuckle's default tag comes from class name without the Controller suffix.
        const string controllerSuffix = "Controller";
        var controllerName = typeof(OpenReferralController).Name;
        var swaggerTag = controllerName.EndsWith(controllerSuffix, StringComparison.Ordinal)
            ? controllerName[..^controllerSuffix.Length]
            : controllerName;

        Assert.That(swaggerTag, Is.EqualTo("OpenReferral"));
        Assert.That(swaggerTag, Is.Not.EqualTo("OpenApi"));
    }
}

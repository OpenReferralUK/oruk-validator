using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Controllers;

namespace OpenReferralApi.Tests.Controllers;

[TestFixture]
public class MockControllerTests
{
    private Mock<ILogger<MockController>> _loggerMock;
    private MockController _controller;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<MockController>>();
        _controller = new MockController(_loggerMock.Object);
    }

    [Test]
    public async Task GetServiceMetadata_DefaultRoute_ReturnsOkResult()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
        };

        // Act
        var result = await _controller.GetServiceMetadata();

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    [Test]
    public async Task GetServices_DefaultRoute_ReturnsOkResult()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
        };

        // Act
        var result = await _controller.GetServices();

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    [Test]
    public async Task GetServicesById_WithValidId_ReturnsOkResult()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
        };

        // Act
        var result = await _controller.GetServicesById();

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    [Test]
    public async Task GetTaxonomies_DefaultRoute_ReturnsOkResult()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
        };

        // Act
        var result = await _controller.GetTaxonomies();

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    [Test]
    public async Task GetServiceAtLocations_DefaultRoute_ReturnsOkResult()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
        };

        // Act
        var result = await _controller.GetServiceAtLocations();

        // Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    [Test]
    public void MockEndpoints_DeclareExpectedProducesResponseTypes()
    {
        var actionNames = new[]
        {
            nameof(MockController.GetServiceMetadata),
            nameof(MockController.GetServices),
            nameof(MockController.GetServicesById),
            nameof(MockController.GetTaxonomies),
            nameof(MockController.GetTaxonomiesById),
            nameof(MockController.GetTaxonomyTerms),
            nameof(MockController.GetTaxonomyTermsById),
            nameof(MockController.GetServiceAtLocations),
            nameof(MockController.GetServiceAtLocationsById),
            nameof(MockController.GetV1ValidatorMock),
            nameof(MockController.GetDashboardMock)
        };

        foreach (var actionName in actionNames)
        {
            var method = typeof(MockController).GetMethod(actionName);
            Assert.That(method, Is.Not.Null, $"Expected action method '{actionName}' to exist");

            var produces = method!
                .GetCustomAttributes(typeof(ProducesResponseTypeAttribute), inherit: false)
                .Cast<ProducesResponseTypeAttribute>()
                .ToList();

            Assert.That(produces.Any(p => p.StatusCode == StatusCodes.Status200OK), Is.True,
                $"Expected '{actionName}' to declare 200 response type");
            Assert.That(produces.Any(p => p.StatusCode == StatusCodes.Status404NotFound), Is.True,
                $"Expected '{actionName}' to declare 404 response type");
            Assert.That(produces.Any(p => p.StatusCode == StatusCodes.Status500InternalServerError), Is.True,
                $"Expected '{actionName}' to declare 500 response type");
        }
    }
}

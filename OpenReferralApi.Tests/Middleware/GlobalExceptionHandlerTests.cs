using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Middleware;
using System.Text.Json;

namespace OpenReferralApi.Tests.Middleware;

[TestFixture]
public class GlobalExceptionHandlerTests
{
    private Mock<ILogger<GlobalExceptionHandler>> _loggerMock;
    private Mock<IHostEnvironment> _environmentMock;
    private GlobalExceptionHandler _handler;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<GlobalExceptionHandler>>();
        _environmentMock = new Mock<IHostEnvironment>();
        _handler = new GlobalExceptionHandler(_loggerMock.Object, _environmentMock.Object);
    }

    [Test]
    public async Task TryHandleAsync_WithException_ReturnsTrue()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var exception = new InvalidOperationException("Test exception");

        _environmentMock.Setup(x => x.EnvironmentName).Returns("Production");

        // Act
        var result = await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(context.Response.StatusCode, Is.EqualTo(400));
    }

    [Test]
    public async Task TryHandleAsync_WithArgumentException_Returns400()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var exception = new ArgumentException("Invalid argument");

        _environmentMock.Setup(x => x.EnvironmentName).Returns("Production");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.That(context.Response.StatusCode, Is.EqualTo(400));
    }

    [Test]
    public async Task TryHandleAsync_WithUnauthorizedException_Returns401()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var exception = new UnauthorizedAccessException("Unauthorized");

        _environmentMock.Setup(x => x.EnvironmentName).Returns("Production");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        Assert.That(context.Response.StatusCode, Is.EqualTo(401));
    }

    [Test]
    public async Task TryHandleAsync_InDevelopment_IncludesStackTrace()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var exception = new InvalidOperationException("Test exception");

        _environmentMock.Setup(x => x.EnvironmentName).Returns("Development");

        // Act
        await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        // Assert
        context.Response.Body.Position = 0;
        var reader = new StreamReader(context.Response.Body);
        var responseBody = await reader.ReadToEndAsync();
        
        Assert.That(responseBody, Does.Contain("stackTrace"));
    }
}

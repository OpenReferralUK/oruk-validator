using Microsoft.AspNetCore.Http;
using OpenReferralApi.Middleware;

namespace OpenReferralApi.Tests.Middleware;

[TestFixture]
public class CorrelationIdMiddlewareTests
{
    [Test]
    public async Task InvokeAsync_WithoutExistingCorrelationId_GeneratesNew()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var nextCalled = false;
        RequestDelegate next = (ctx) =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new CorrelationIdMiddleware(next);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.That(nextCalled, Is.True);
        Assert.That(context.Items, Does.ContainKey("CorrelationId"));
        Assert.That(context.Items["CorrelationId"], Is.Not.Null);
        Assert.That(context.Response.Headers, Does.ContainKey("X-Correlation-ID"));
    }

    [Test]
    public async Task InvokeAsync_WithExistingCorrelationId_UsesExisting()
    {
        // Arrange
        var existingCorrelationId = Guid.NewGuid().ToString();
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Correlation-ID"] = existingCorrelationId;

        var nextCalled = false;
        RequestDelegate next = (ctx) =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new CorrelationIdMiddleware(next);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.That(nextCalled, Is.True);
        Assert.That(context.Items["CorrelationId"], Is.EqualTo(existingCorrelationId));
        Assert.That(context.Response.Headers["X-Correlation-ID"].ToString(), Is.EqualTo(existingCorrelationId));
    }
}

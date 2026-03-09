using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using OpenReferralApi.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class SchemaWarmupBackgroundServiceTests
{
    [Test]
    public async Task ExecuteAsync_WhenDisabled_SetsSkippedStatus()
    {
        var resolverMock = new Mock<ISchemaResolverService>();
        using var serviceProvider = BuildServiceProvider(resolverMock.Object);
        var statusTracker = new SchemaWarmupStatusTracker();
        var logger = new Mock<ILogger<SchemaWarmupBackgroundService>>();

        var service = new TestableSchemaWarmupBackgroundService(
            serviceProvider,
            Options.Create(new SchemaWarmupOptions { Enabled = false }),
            Options.Create(new CacheOptions { Enabled = true }),
            statusTracker,
            logger.Object);

        await service.RunOnce(CancellationToken.None);

        var snapshot = statusTracker.GetSnapshot();
        Assert.That(snapshot.State, Is.EqualTo("skipped"));
        Assert.That(snapshot.SkipReason, Is.EqualTo("disabled"));
        resolverMock.Verify(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null), Times.Never);
    }

    [Test]
    public async Task ExecuteAsync_WhenCacheDisabled_SetsSkippedStatus()
    {
        var resolverMock = new Mock<ISchemaResolverService>();
        using var serviceProvider = BuildServiceProvider(resolverMock.Object);
        var statusTracker = new SchemaWarmupStatusTracker();
        var logger = new Mock<ILogger<SchemaWarmupBackgroundService>>();

        var service = new TestableSchemaWarmupBackgroundService(
            serviceProvider,
            Options.Create(new SchemaWarmupOptions
            {
                Enabled = true,
                Urls = new List<string> { "https://example.com/schema.json" }
            }),
            Options.Create(new CacheOptions { Enabled = false }),
            statusTracker,
            logger.Object);

        await service.RunOnce(CancellationToken.None);

        var snapshot = statusTracker.GetSnapshot();
        Assert.That(snapshot.State, Is.EqualTo("skipped"));
        Assert.That(snapshot.SkipReason, Is.EqualTo("cache-disabled"));
        resolverMock.Verify(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null), Times.Never);
    }

    [Test]
    public async Task ExecuteAsync_WithMixedResults_TracksCountsAndFailureState()
    {
        var successUrl = "https://example.com/schema-success.json";
        var failUrl = "https://example.com/schema-fail.json";

        var resolverMock = new Mock<ISchemaResolverService>();
        resolverMock
            .Setup(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null))
            .Returns<string, string?, DataSourceAuthentication?>((_, baseUri, _) =>
            {
                if (string.Equals(baseUri, failUrl, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("warmup failure");
                }

                return Task.FromResult("{}");
            });

        using var serviceProvider = BuildServiceProvider(resolverMock.Object);
        var statusTracker = new SchemaWarmupStatusTracker();
        var logger = new Mock<ILogger<SchemaWarmupBackgroundService>>();

        var service = new TestableSchemaWarmupBackgroundService(
            serviceProvider,
            Options.Create(new SchemaWarmupOptions
            {
                Enabled = true,
                StartupDelaySeconds = 0,
                Urls = new List<string> { successUrl, failUrl }
            }),
            Options.Create(new CacheOptions { Enabled = true }),
            statusTracker,
            logger.Object);

        await service.RunOnce(CancellationToken.None);

        var snapshot = statusTracker.GetSnapshot();
        Assert.That(snapshot.State, Is.EqualTo("completed-with-errors"));
        Assert.That(snapshot.ConfiguredUrlCount, Is.EqualTo(2));
        Assert.That(snapshot.AttemptedCount, Is.EqualTo(2));
        Assert.That(snapshot.SucceededCount, Is.EqualTo(1));
        Assert.That(snapshot.FailedCount, Is.EqualTo(1));
        Assert.That(snapshot.LastFailureUrl, Is.EqualTo(failUrl));
    }

    [Test]
    public async Task ExecuteAsync_WithDuplicateUrls_DeduplicatesRequests()
    {
        var resolverMock = new Mock<ISchemaResolverService>();
        resolverMock
            .Setup(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null))
            .ReturnsAsync("{}");

        using var serviceProvider = BuildServiceProvider(resolverMock.Object);
        var statusTracker = new SchemaWarmupStatusTracker();
        var logger = new Mock<ILogger<SchemaWarmupBackgroundService>>();

        var canonicalUrl = "https://example.com/schema.json";

        var service = new TestableSchemaWarmupBackgroundService(
            serviceProvider,
            Options.Create(new SchemaWarmupOptions
            {
                Enabled = true,
                StartupDelaySeconds = 0,
                Urls = new List<string>
                {
                    canonicalUrl,
                    $" {canonicalUrl} ",
                    "HTTPS://EXAMPLE.COM/SCHEMA.JSON"
                }
            }),
            Options.Create(new CacheOptions { Enabled = true }),
            statusTracker,
            logger.Object);

        await service.RunOnce(CancellationToken.None);

        var snapshot = statusTracker.GetSnapshot();
        Assert.That(snapshot.State, Is.EqualTo("completed"));
        Assert.That(snapshot.ConfiguredUrlCount, Is.EqualTo(1));
        Assert.That(snapshot.AttemptedCount, Is.EqualTo(1));
        Assert.That(snapshot.SucceededCount, Is.EqualTo(1));

        resolverMock.Verify(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null), Times.Once);
    }

    [Test]
    public async Task ExecuteAsync_WhenCancelledBeforeLoop_MarksCancelled()
    {
        var resolverMock = new Mock<ISchemaResolverService>();
        resolverMock
            .Setup(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null))
            .ReturnsAsync("{}");

        using var serviceProvider = BuildServiceProvider(resolverMock.Object);
        var statusTracker = new SchemaWarmupStatusTracker();
        var logger = new Mock<ILogger<SchemaWarmupBackgroundService>>();

        var service = new TestableSchemaWarmupBackgroundService(
            serviceProvider,
            Options.Create(new SchemaWarmupOptions
            {
                Enabled = true,
                StartupDelaySeconds = 0,
                Urls = new List<string> { "https://example.com/schema.json" }
            }),
            Options.Create(new CacheOptions { Enabled = true }),
            statusTracker,
            logger.Object);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await service.RunOnce(cts.Token);

        var snapshot = statusTracker.GetSnapshot();
        Assert.That(snapshot.State, Is.EqualTo("cancelled"));
        Assert.That(snapshot.ConfiguredUrlCount, Is.EqualTo(1));
        Assert.That(snapshot.AttemptedCount, Is.EqualTo(0));

        resolverMock.Verify(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), null), Times.Never);
    }

    private static ServiceProvider BuildServiceProvider(ISchemaResolverService resolver)
    {
        var services = new ServiceCollection();
        services.AddScoped<ISchemaResolverService>(_ => resolver);
        return services.BuildServiceProvider();
    }

    private sealed class TestableSchemaWarmupBackgroundService : SchemaWarmupBackgroundService
    {
        public TestableSchemaWarmupBackgroundService(
            IServiceProvider serviceProvider,
            IOptions<SchemaWarmupOptions> options,
            IOptions<CacheOptions> cacheOptions,
            ISchemaWarmupStatusTracker statusTracker,
            ILogger<SchemaWarmupBackgroundService> logger)
            : base(serviceProvider, options, cacheOptions, statusTracker, logger)
        {
        }

        public Task RunOnce(CancellationToken cancellationToken)
        {
            return ExecuteAsync(cancellationToken);
        }
    }
}

using Microsoft.Extensions.Options;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Services;

/// <summary>
/// Warms frequently-used remote schemas into cache after startup.
/// </summary>
public class SchemaWarmupBackgroundService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SchemaWarmupBackgroundService> _logger;
    private readonly SchemaWarmupOptions _options;
    private readonly CacheOptions _cacheOptions;
    private readonly ISchemaWarmupStatusTracker _statusTracker;

    public SchemaWarmupBackgroundService(
        IServiceProvider serviceProvider,
        IOptions<SchemaWarmupOptions> options,
        IOptions<CacheOptions> cacheOptions,
        ISchemaWarmupStatusTracker statusTracker,
        ILogger<SchemaWarmupBackgroundService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _options = options.Value ?? new SchemaWarmupOptions();
        _cacheOptions = cacheOptions.Value ?? new CacheOptions();
        _statusTracker = statusTracker;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _statusTracker.MarkSkipped("disabled");
            _logger.LogInformation("Schema warmup is disabled.");
            return;
        }

        if (!_cacheOptions.Enabled)
        {
            _statusTracker.MarkSkipped("cache-disabled");
            _logger.LogInformation("Schema warmup is skipped because cache is disabled.");
            return;
        }

        var urls = (_options.Urls ?? new List<string>())
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Select(url => url.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (urls.Count == 0)
        {
            _statusTracker.MarkSkipped("no-urls");
            _logger.LogInformation("Schema warmup is enabled but no URLs are configured.");
            return;
        }

        _statusTracker.MarkStarted(urls.Count);

        var delaySeconds = Math.Max(0, _options.StartupDelaySeconds);
        if (delaySeconds > 0)
        {
            _logger.LogInformation("Schema warmup starting in {DelaySeconds}s.", delaySeconds);
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
        }

        using var scope = _serviceProvider.CreateScope();
        var resolver = scope.ServiceProvider.GetRequiredService<ISchemaResolverService>();

        _logger.LogInformation("Starting schema warmup for {Count} URL(s).", urls.Count);

        foreach (var url in urls)
        {
            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                // A root $ref forces the resolver to fetch and recursively resolve dependencies.
                var warmupSchema = $$"""
                {
                  "$ref": "{{url}}"
                }
                """;

                await resolver.ResolveAsync(warmupSchema, url, auth: null);
                _statusTracker.MarkSuccess();
                _logger.LogInformation("Schema warmup succeeded: {SchemaUrl}", SchemaResolverService.SanitizeUrlForLogging(url));
            }
            catch (Exception ex)
            {
                _statusTracker.MarkFailure(url);
                _logger.LogWarning(ex, "Schema warmup failed: {SchemaUrl}", SchemaResolverService.SanitizeUrlForLogging(url));
            }
        }

        _statusTracker.MarkCompleted(stoppingToken.IsCancellationRequested);
        _logger.LogInformation("Schema warmup completed.");
    }
}

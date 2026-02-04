using System.Diagnostics;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Services;

/// <summary>
/// Background service that validates registered feeds every 24 hours at midnight
/// </summary>
public class FeedValidationBackgroundService : BackgroundService
{
  private readonly IServiceProvider _serviceProvider;
  private readonly ILogger<FeedValidationBackgroundService> _logger;
  private readonly TimeSpan _validationInterval;
  private readonly bool _runAtMidnight;
  private readonly bool _enabled;

  public FeedValidationBackgroundService(
      IServiceProvider serviceProvider,
      IConfiguration configuration,
      ILogger<FeedValidationBackgroundService> logger)
  {
    _serviceProvider = serviceProvider;
    _logger = logger;

    // Read configuration
    _enabled = configuration.GetValue<bool>("FeedValidation:Enabled", false);
    _validationInterval = TimeSpan.FromHours(
        configuration.GetValue<double>("FeedValidation:IntervalHours", 24));
    _runAtMidnight = configuration.GetValue<bool>("FeedValidation:RunAtMidnight", true);
  }

  protected override async Task ExecuteAsync(CancellationToken stoppingToken)
  {
    if (!_enabled)
    {
      _logger.LogInformation(
          "Feed Validation Background Service is disabled. Set FeedValidation:Enabled=true to enable.");
      return;
    }

    _logger.LogInformation(
        "Feed Validation Background Service started. Interval: {Interval} hours, RunAtMidnight: {RunAtMidnight}",
        _validationInterval.TotalHours, _runAtMidnight);

    // Wait until first scheduled run
    await WaitForNextScheduledRunAsync(stoppingToken);

    while (!stoppingToken.IsCancellationRequested)
    {
      try
      {
        _logger.LogInformation("Starting scheduled feed validation run at {Time}", DateTime.UtcNow);
        await ValidateAllFeedsAsync(stoppingToken);
        _logger.LogInformation("Completed scheduled feed validation run at {Time}", DateTime.UtcNow);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error during scheduled feed validation");
      }

      // Wait for next scheduled run
      await WaitForNextScheduledRunAsync(stoppingToken);
    }
  }

  private async Task WaitForNextScheduledRunAsync(CancellationToken cancellationToken)
  {
    TimeSpan delay;

    if (_runAtMidnight)
    {
      // Calculate time until next midnight UTC
      var now = DateTime.UtcNow;
      var nextMidnight = now.Date.AddDays(1);
      delay = nextMidnight - now;

      _logger.LogInformation(
          "Next validation scheduled for {NextRun} (in {Hours:F1} hours)",
          nextMidnight, delay.TotalHours);
    }
    else
    {
      // Use fixed interval
      delay = _validationInterval;
      _logger.LogInformation(
          "Next validation scheduled in {Hours:F1} hours",
          delay.TotalHours);
    }

    try
    {
      await Task.Delay(delay, cancellationToken);
    }
    catch (TaskCanceledException)
    {
      _logger.LogInformation("Feed validation service is stopping");
    }
  }

  private async Task ValidateAllFeedsAsync(CancellationToken cancellationToken)
  {
    var stopwatch = Stopwatch.StartNew();

    using var scope = _serviceProvider.CreateScope();
    var feedValidationService = scope.ServiceProvider.GetRequiredService<IFeedValidationService>();

    try
    {
      // Get all registered feeds
      var feeds = await feedValidationService.GetAllFeedsAsync(cancellationToken);

      _logger.LogInformation("Found {FeedCount} registered feeds to validate", feeds.Count);

      if (feeds.Count == 0)
      {
        _logger.LogWarning("No feeds found in database");
        return;
      }

      // Use SemaphoreSlim to limit concurrent validations and prevent overwhelming the dyno
      var maxConcurrency = 5; // Process 5 feeds at a time to maintain web server responsiveness
      using var semaphore = new SemaphoreSlim(maxConcurrency);
      
      var tasks = feeds.Select(async feed =>
      {
        await semaphore.WaitAsync(cancellationToken);
        try
        {
          var result = await feedValidationService.ValidateSingleFeedAsync(feed, cancellationToken);

          await feedValidationService.UpdateFeedStatusAsync(
                    feedId: result.FeedId,
                    isUp: result.IsUp,
                    isValid: result.IsValid,
                    error: result.ErrorMessage,
                    responseTimeMs: result.ResponseTimeMs,
                    validationErrorCount: result.ValidationErrorCount,
                    cancellationToken: cancellationToken);

          return result;
        }
        catch (Exception ex)
        {
          _logger.LogError(ex, "Failed to validate feed {FeedId}", feed.Id);
          return null;
        }
        finally
        {
          semaphore.Release();
        }
      });

      var results = await Task.WhenAll(tasks);

      // Log summary
      var successCount = results.Count(r => r?.IsUp == true);
      var validCount = results.Count(r => r?.IsValid == true);
      var failedCount = results.Count(r => r?.IsUp == false);

      stopwatch.Stop();

      _logger.LogInformation(
          "Feed validation summary: Total={Total}, Up={Up}, Valid={Valid}, Down={Down}, Duration={Duration}s",
          feeds.Count, successCount, validCount, failedCount, stopwatch.Elapsed.TotalSeconds);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error validating feeds");
    }
  }

  public override async Task StopAsync(CancellationToken cancellationToken)
  {
    _logger.LogInformation("Feed Validation Background Service is stopping");
    await base.StopAsync(cancellationToken);
  }
}

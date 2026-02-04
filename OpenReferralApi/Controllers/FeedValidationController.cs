using Microsoft.AspNetCore.Mvc;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Controllers;

/// <summary>
/// Controller for managing and testing feed validation
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class FeedValidationController : ControllerBase
{
  private readonly IFeedValidationService _feedValidationService;
  private readonly ILogger<FeedValidationController> _logger;

  public FeedValidationController(
      IFeedValidationService feedValidationService,
      ILogger<FeedValidationController> logger)
  {
    _feedValidationService = feedValidationService;
    _logger = logger;
  }

  /// <summary>
  /// Get all registered feeds with their current status
  /// </summary>
  /// <returns>List of all feeds</returns>
  [HttpGet("feeds")]
  [ProducesResponseType(typeof(List<ServiceFeed>), StatusCodes.Status200OK)]
  public async Task<ActionResult<List<ServiceFeed>>> GetAllFeeds(CancellationToken cancellationToken)
  {
    try
    {
      var feeds = await _feedValidationService.GetAllFeedsAsync(cancellationToken);
      return Ok(feeds);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error retrieving feeds");
      return StatusCode(500, new { error = "Failed to retrieve feeds", message = ex.Message });
    }
  }

  /// <summary>
  /// Manually trigger validation for all feeds
  /// </summary>
  /// <returns>Validation results for all feeds</returns>
  [HttpPost("validate-all")]
  [ProducesResponseType(typeof(FeedValidationSummary), StatusCodes.Status200OK)]
  public async Task<ActionResult<FeedValidationSummary>> ValidateAllFeeds(CancellationToken cancellationToken)
  {
    try
    {
      _logger.LogInformation("Manual validation triggered for all feeds");

      var feeds = await _feedValidationService.GetAllFeedsAsync(cancellationToken);

      if (feeds.Count == 0)
      {
        return Ok(new FeedValidationSummary
        {
          TotalFeeds = 0,
          Message = "No feeds found in database"
        });
      }

      // Validate feeds in parallel to avoid timeouts (same pattern as background service)
      // Use SemaphoreSlim to limit concurrent validations
      var maxConcurrency = 5; // Process 5 feeds at a time
      using var semaphore = new SemaphoreSlim(maxConcurrency);
      
      var tasks = feeds.Select(async feed =>
      {
        await semaphore.WaitAsync(cancellationToken);
        try
        {
          var result = await _feedValidationService.ValidateSingleFeedAsync(feed, cancellationToken);

          await _feedValidationService.UpdateFeedStatusAsync(
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
          return new FeedValidationResult
          {
            FeedId = feed.Id ?? string.Empty,
            FeedUrl = feed.Url,
            FeedName = feed.NameAsString,
            IsUp = false,
            IsValid = false,
            ErrorMessage = $"Validation error: {ex.Message}"
          };
        }
        finally
        {
          semaphore.Release();
        }
      });

      var results = await Task.WhenAll(tasks);

      var summary = new FeedValidationSummary
      {
        TotalFeeds = feeds.Count,
        UpFeeds = results.Count(r => r.IsUp),
        ValidFeeds = results.Count(r => r.IsValid),
        DownFeeds = results.Count(r => !r.IsUp),
        InvalidFeeds = results.Count(r => r.IsUp && !r.IsValid),
        AverageResponseTimeMs = results.Where(r => r.ResponseTimeMs.HasValue)
              .Average(r => r.ResponseTimeMs),
        Results = results.ToList()
      };

      _logger.LogInformation(
          "Manual validation completed: {Total} feeds, {Up} up, {Valid} valid",
          summary.TotalFeeds, summary.UpFeeds, summary.ValidFeeds);

      return Ok(summary);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error during manual validation");
      return StatusCode(500, new { error = "Validation failed", message = ex.Message });
    }
  }

  /// <summary>
  /// Manually trigger validation for a specific feed by ID
  /// </summary>
  /// <param name="feedId">The MongoDB ObjectId of the feed</param>
  /// <param name="cancellationToken">Cancellation token</param>
  /// <returns>Validation result for the specified feed</returns>
  [HttpPost("validate/{feedId}")]
  [ProducesResponseType(typeof(FeedValidationResult), StatusCodes.Status200OK)]
  [ProducesResponseType(StatusCodes.Status404NotFound)]
  public async Task<ActionResult<FeedValidationResult>> ValidateFeed(
      string feedId,
      CancellationToken cancellationToken)
  {
    try
    {
      var feeds = await _feedValidationService.GetAllFeedsAsync(cancellationToken);
      var feed = feeds.FirstOrDefault(f => f.Id == feedId);

      if (feed == null)
      {
        return NotFound(new { error = "Feed not found", feedId });
      }

      _logger.LogInformation("Manual validation triggered for feed {FeedId}", feedId);

      var result = await _feedValidationService.ValidateSingleFeedAsync(feed, cancellationToken);

      await _feedValidationService.UpdateFeedStatusAsync(
          feedId: result.FeedId,
          isUp: result.IsUp,
          isValid: result.IsValid,
          error: result.ErrorMessage,
          responseTimeMs: result.ResponseTimeMs,
          validationErrorCount: result.ValidationErrorCount,
          cancellationToken: cancellationToken);

      return Ok(result);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error validating feed {FeedId}", feedId);
      return StatusCode(500, new { error = "Validation failed", message = ex.Message });
    }
  }
}

/// <summary>
/// Summary of feed validation results
/// </summary>
public class FeedValidationSummary
{
  public int TotalFeeds { get; set; }
  public int UpFeeds { get; set; }
  public int ValidFeeds { get; set; }
  public int DownFeeds { get; set; }
  public int InvalidFeeds { get; set; }
  public double? AverageResponseTimeMs { get; set; }
  public string? Message { get; set; }
  public List<FeedValidationResult> Results { get; set; } = new();
}

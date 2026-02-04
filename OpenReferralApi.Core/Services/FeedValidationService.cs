using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using MongoDB.Bson;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for validating registered feeds and updating their status
/// </summary>
public interface IFeedValidationService
{
  Task<List<ServiceFeed>> GetAllFeedsAsync(CancellationToken cancellationToken = default);
  Task UpdateFeedStatusAsync(string feedId, bool isUp, bool isValid, string? error, double? responseTimeMs, int? validationErrorCount, CancellationToken cancellationToken = default);
  Task<FeedValidationResult> ValidateSingleFeedAsync(ServiceFeed feed, CancellationToken cancellationToken = default);
}

public class FeedValidationService : IFeedValidationService
{
  private readonly IMongoCollection<ServiceFeed> _servicesCollection;
  private readonly IOpenApiValidationService _validationService;
  private readonly ILogger<FeedValidationService> _logger;

  public FeedValidationService(
      IMongoClient mongoClient,
      IConfiguration configuration,
      IOpenApiValidationService validationService,
      ILogger<FeedValidationService> logger)
  {
    var databaseName = configuration.GetValue<string>("Database:DatabaseName") ?? "oruk-v3";
    var database = mongoClient.GetDatabase(databaseName);
    _servicesCollection = database.GetCollection<ServiceFeed>("services");
    _validationService = validationService;
    _logger = logger;
  }

  public async Task<List<ServiceFeed>> GetAllFeedsAsync(CancellationToken cancellationToken = default)
  {
    try
    {
      // Filter for active feeds - check for boolean true, string "true", or nested value
      var filter = Builders<ServiceFeed>.Filter.Or(
          Builders<ServiceFeed>.Filter.Eq(f => f.ActiveField, true),
          Builders<ServiceFeed>.Filter.Eq(f => f.ActiveField, "true"),
          Builders<ServiceFeed>.Filter.Regex("active.value", new System.Text.RegularExpressions.Regex("^true$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
      );

      return await _servicesCollection
          .Find(filter)
          .ToListAsync(cancellationToken);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to retrieve feeds from database");
      return new List<ServiceFeed>();
    }
  }

  public async Task UpdateFeedStatusAsync(
      string feedId,
      bool isUp,
      bool isValid,
      string? error,
      double? responseTimeMs,
      int? validationErrorCount,
      CancellationToken cancellationToken = default)
  {
    try
    {
      var filter = Builders<ServiceFeed>.Filter.Eq(f => f.Id, feedId);

      // Read the current document to check structure of existing status fields
      var currentFeed = await _servicesCollection.Find(filter).FirstOrDefaultAsync(cancellationToken);
      if (currentFeed == null)
      {
        _logger.LogWarning("Feed {FeedId} not found for update", feedId);
        return;
      }

      var updateBuilder = Builders<ServiceFeed>.Update;
      var updates = new List<UpdateDefinition<ServiceFeed>>();

      // For status fields, if they exist as BsonDocuments, update nested value field
      // otherwise set as simple boolean
      if (currentFeed.StatusIsUp?.IsBsonDocument ?? false)
      {
        updates.Add(updateBuilder.Set("statusIsUp.value", isUp));
      }
      else
      {
        updates.Add(updateBuilder.Set(f => f.StatusIsUp, isUp));
      }

      if (currentFeed.StatusIsValid?.IsBsonDocument ?? false)
      {
        updates.Add(updateBuilder.Set("statusIsValid.value", isValid));
      }
      else
      {
        updates.Add(updateBuilder.Set(f => f.StatusIsValid, isValid));
      }

      if (currentFeed.StatusOverall?.IsBsonDocument ?? false)
      {
        updates.Add(updateBuilder.Set("statusOverall.value", isValid));
      }
      else
      {
        updates.Add(updateBuilder.Set(f => f.StatusOverall, isValid));
      }

      updates.Add(updateBuilder.Set(f => f.LastChecked, DateTime.UtcNow));
      updates.Add(updateBuilder.Set(f => f.LastError, error));
      updates.Add(updateBuilder.Set(f => f.ResponseTimeMs, responseTimeMs));
      updates.Add(updateBuilder.Set(f => f.ValidationErrorCount, validationErrorCount));

      var combinedUpdate = updateBuilder.Combine(updates);
      await _servicesCollection.UpdateOneAsync(filter, combinedUpdate, cancellationToken: cancellationToken);

      _logger.LogInformation(
          "Updated feed {FeedId}: IsUp={IsUp}, IsValid={IsValid}, ResponseTime={ResponseTime}ms, Errors={ErrorCount}",
          feedId, isUp, isValid, responseTimeMs, validationErrorCount);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to update feed status for feed {FeedId}", feedId);
    }
  }

  public async Task<FeedValidationResult> ValidateSingleFeedAsync(
      ServiceFeed feed,
      CancellationToken cancellationToken = default)
  {
    var result = new FeedValidationResult
    {
      FeedId = feed.Id!,
      FeedUrl = feed.Url,
      FeedName = feed.NameAsString
    };

    try
    {
      _logger.LogInformation("Validating feed: {FeedName} ({FeedUrl})", feed.NameAsString ?? "Unnamed", feed.Url);

      var validationRequest = new OpenApiValidationRequest
      {
        BaseUrl = feed.Url,
        Options = new OpenApiValidationOptions
        {
          ValidateSpecification = true,
          TestEndpoints = true,
          TestOptionalEndpoints = true,
          TreatOptionalEndpointsAsWarnings = true,
          TimeoutSeconds = 60,
          MaxConcurrentRequests = 10
        }
      };

      var validationResult = await _validationService.ValidateOpenApiSpecificationAsync(
          validationRequest,
          cancellationToken);

      // IsUp is true if any endpoint test result was successful
      result.IsUp = validationResult.EndpointTests
          .SelectMany(e => e.TestResults)
          .Any(tr => tr.IsSuccess);
      result.IsValid = validationResult.IsValid;
      result.ResponseTimeMs = validationResult.Duration.TotalMilliseconds;
      
      // Count all validation errors from endpoint test results
      result.ValidationErrorCount = validationResult.EndpointTests
          .SelectMany(e => e.TestResults)
          .Sum(tr => tr.ValidationResult?.Errors.Count ?? 0);

      if (!validationResult.IsValid)
      {
        // Extract error messages from endpoint test results
        var errors = validationResult.EndpointTests
            .SelectMany(e => e.TestResults)
            .Where(tr => tr.ValidationResult != null)
            .SelectMany(tr => tr.ValidationResult!.Errors)
            .Take(5)
            .Select(e => $"{e.Path}: {e.Message}")
            .ToList();

        result.ErrorMessage = errors.Any()
            ? string.Join("; ", errors)
            : "Validation failed with no specific errors";
      }

      _logger.LogInformation(
          "Feed validation completed: {FeedName} - IsUp={IsUp}, IsValid={IsValid}, Errors={ErrorCount}",
          feed.NameAsString ?? "Unnamed", result.IsUp, result.IsValid, result.ValidationErrorCount);
    }
    catch (HttpRequestException ex)
    {
      _logger.LogWarning(ex, "Feed is not accessible: {FeedUrl}", feed.Url);
      result.IsUp = false;
      result.IsValid = false;
      result.ErrorMessage = $"HTTP error: {ex.Message}";
    }
    catch (TaskCanceledException ex)
    {
      _logger.LogWarning(ex, "Feed validation timed out: {FeedUrl}", feed.Url);
      result.IsUp = false;
      result.IsValid = false;
      result.ErrorMessage = "Request timed out";
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Unexpected error validating feed: {FeedUrl}", feed.Url);
      result.IsUp = false;
      result.IsValid = false;
      result.ErrorMessage = $"Unexpected error: {ex.Message}";
    }

    return result;
  }
}

/// <summary>
/// Null implementation when MongoDB is not configured
/// </summary>
public class NullFeedValidationService : IFeedValidationService
{
  private readonly ILogger<NullFeedValidationService> _logger;

  public NullFeedValidationService(ILogger<NullFeedValidationService> logger)
  {
    _logger = logger;
  }

  public Task<List<ServiceFeed>> GetAllFeedsAsync(CancellationToken cancellationToken = default)
  {
    _logger.LogWarning("Feed validation service is not available. MongoDB is not configured.");
    return Task.FromResult(new List<ServiceFeed>());
  }

  public Task UpdateFeedStatusAsync(string feedId, bool isUp, bool isValid, string? error, double? responseTimeMs, int? validationErrorCount, CancellationToken cancellationToken = default)
  {
    _logger.LogWarning("Feed validation service is not available. MongoDB is not configured.");
    return Task.CompletedTask;
  }

  public Task<FeedValidationResult> ValidateSingleFeedAsync(ServiceFeed feed, CancellationToken cancellationToken = default)
  {
    _logger.LogWarning("Feed validation service is not available. MongoDB is not configured.");
    return Task.FromResult(new FeedValidationResult
    {
      FeedId = feed.Id ?? string.Empty,
      FeedUrl = feed.Url,
      FeedName = feed.NameAsString,
      IsUp = false,
      IsValid = false,
      ErrorMessage = "Feed validation service is not available. MongoDB is not configured."
    });
  }
}

/// <summary>
/// Result of validating a single feed
/// </summary>
public class FeedValidationResult
{
  public string FeedId { get; set; } = string.Empty;
  public string FeedUrl { get; set; } = string.Empty;
  public string? FeedName { get; set; }
  public bool IsUp { get; set; }
  public bool IsValid { get; set; }
  public string? ErrorMessage { get; set; }
  public double? ResponseTimeMs { get; set; }
  public int ValidationErrorCount { get; set; }
}

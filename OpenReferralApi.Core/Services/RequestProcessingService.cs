using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for managing concurrent request processing, throttling, and resource management
/// </summary>
public interface IRequestProcessingService
{
    /// <summary>
    /// Executes a function with concurrency control and throttling
    /// </summary>
    /// <typeparam name="T">Return type of the function</typeparam>
    /// <param name="function">The function to execute</param>
    /// <param name="options">Validation options containing concurrency settings</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Result of the function execution</returns>
    Task<T> ExecuteWithConcurrencyControlAsync<T>(
        Func<CancellationToken, Task<T>> function,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes multiple functions concurrently with proper throttling
    /// </summary>
    /// <typeparam name="T">Return type of the functions</typeparam>
    /// <param name="functions">Collection of functions to execute</param>
    /// <param name="options">Validation options containing concurrency settings</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Collection of results from all function executions</returns>
    Task<IEnumerable<T>> ExecuteMultipleConcurrentlyAsync<T>(
        IEnumerable<Func<CancellationToken, Task<T>>> functions,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes a function with retry logic
    /// </summary>
    /// <typeparam name="T">Return type of the function</typeparam>
    /// <param name="function">The function to execute</param>
    /// <param name="options">Validation options containing retry settings</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Result of the function execution</returns>
    Task<T> ExecuteWithRetryAsync<T>(
        Func<CancellationToken, Task<T>> function,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a timeout-controlled cancellation token
    /// </summary>
    /// <param name="options">Validation options containing timeout settings</param>
    /// <param name="parentToken">Parent cancellation token to link</param>
    /// <returns>Cancellation token source with timeout</returns>
    CancellationTokenSource CreateTimeoutToken(ValidationOptions? options = null, CancellationToken parentToken = default);

    /// <summary>
    /// Gets current resource utilization metrics
    /// </summary>
    /// <returns>Resource utilization information</returns>
    Task<ResourceUtilizationMetrics> GetResourceMetricsAsync();
}

/// <summary>
/// Metrics about current resource utilization
/// </summary>
public class ResourceUtilizationMetrics
{
    public int ActiveRequests { get; set; }
    public int QueuedRequests { get; set; }
    public int MaxConcurrentRequests { get; set; }
    public double AverageResponseTime { get; set; }
    public DateTime LastRequestTime { get; set; }
    public int TotalRequestsProcessed { get; set; }
    public int FailedRequests { get; set; }
}

/// <summary>
/// Service for managing concurrent request processing, throttling, and resource management
/// </summary>
public class RequestProcessingService : IRequestProcessingService, IDisposable
{
    private readonly ILogger<RequestProcessingService> _logger;
    private readonly SemaphoreSlim _concurrencyLimiter;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _namedSemaphores;
    private readonly ConcurrentQueue<DateTime> _requestTimes;
    private readonly object _metricsLock = new();

    private int _activeRequests;
    private int _totalRequestsProcessed;
    private int _failedRequests;
    private DateTime _lastRequestTime = DateTime.MinValue;
    private bool _disposed;

    // Default configuration
    private const int DefaultMaxConcurrentRequests = 5;
    private const int DefaultRetryAttempts = 3;
    private const int DefaultRetryDelaySeconds = 1;
    private const int DefaultTimeoutSeconds = 30;

    public RequestProcessingService(ILogger<RequestProcessingService> logger)
    {
        _logger = logger;
        _concurrencyLimiter = new SemaphoreSlim(DefaultMaxConcurrentRequests, DefaultMaxConcurrentRequests);
        _namedSemaphores = new ConcurrentDictionary<string, SemaphoreSlim>();
        _requestTimes = new ConcurrentQueue<DateTime>();
    }

    public async Task<T> ExecuteWithConcurrencyControlAsync<T>(
        Func<CancellationToken, Task<T>> function,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var maxConcurrent = options?.MaxConcurrentRequests ?? DefaultMaxConcurrentRequests;
        var useThrottling = options?.UseThrottling ?? true;

        // Get or create semaphore for this concurrency level
        var semaphore = GetOrCreateSemaphore(maxConcurrent.ToString(), maxConcurrent);

        if (useThrottling)
        {
            await semaphore.WaitAsync(cancellationToken);
        }
        else
        {
            if (!await semaphore.WaitAsync(0, cancellationToken))
            {
                throw new InvalidOperationException("Maximum concurrent requests exceeded and throttling is disabled");
            }
        }

        try
        {
            Interlocked.Increment(ref _activeRequests);
            _lastRequestTime = DateTime.UtcNow;

            _logger.LogDebug("Executing function with concurrency control. Active: {ActiveRequests}, Max: {MaxConcurrent}",
                _activeRequests, maxConcurrent);

            var stopwatch = Stopwatch.StartNew();
            var result = await function(cancellationToken);
            stopwatch.Stop();

            // Track response times
            _requestTimes.Enqueue(DateTime.UtcNow);
            CleanupOldRequestTimes();

            Interlocked.Increment(ref _totalRequestsProcessed);

            _logger.LogDebug("Function executed successfully in {ElapsedMs}ms", stopwatch.ElapsedMilliseconds);
            return result;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _failedRequests);
            _logger.LogError(ex, "Function execution failed");
            throw;
        }
        finally
        {
            Interlocked.Decrement(ref _activeRequests);
            semaphore.Release();
        }
    }

    public async Task<IEnumerable<T>> ExecuteMultipleConcurrentlyAsync<T>(
        IEnumerable<Func<CancellationToken, Task<T>>> functions,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var functionList = functions.ToList();
        if (!functionList.Any())
        {
            return Enumerable.Empty<T>();
        }

        _logger.LogInformation("Executing {FunctionCount} functions concurrently", functionList.Count);

        var tasks = functionList.Select(func =>
            ExecuteWithConcurrencyControlAsync(func, options, cancellationToken));

        try
        {
            var results = await Task.WhenAll(tasks);
            _logger.LogInformation("Successfully executed {FunctionCount} concurrent functions", functionList.Count);
            return results;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing multiple concurrent functions");
            throw;
        }
    }

    public async Task<T> ExecuteWithRetryAsync<T>(
        Func<CancellationToken, Task<T>> function,
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var maxRetries = options?.RetryAttempts ?? DefaultRetryAttempts;
        var retryDelay = TimeSpan.FromSeconds(options?.RetryDelaySeconds ?? DefaultRetryDelaySeconds);

        Exception? lastException = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                if (attempt > 0)
                {
                    _logger.LogDebug("Retry attempt {Attempt}/{MaxRetries} after {DelayMs}ms",
                        attempt, maxRetries, retryDelay.TotalMilliseconds);

                    await Task.Delay(retryDelay, cancellationToken);

                    // Exponential backoff
                    retryDelay = TimeSpan.FromMilliseconds(retryDelay.TotalMilliseconds * 1.5);
                }

                return await function(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _logger.LogWarning("Function execution cancelled during retry attempt {Attempt}", attempt);
                throw;
            }
            catch (Exception ex)
            {
                lastException = ex;

                if (attempt == maxRetries)
                {
                    _logger.LogError(ex, "Function execution failed after {MaxRetries} retries", maxRetries);
                    break;
                }

                if (IsRetriableException(ex))
                {
                    _logger.LogWarning(ex, "Retriable exception on attempt {Attempt}/{MaxRetries}: {ErrorMessage}",
                        attempt + 1, maxRetries + 1, ex.Message);
                }
                else
                {
                    _logger.LogError(ex, "Non-retriable exception on attempt {Attempt}, aborting retries", attempt + 1);
                    throw;
                }
            }
        }

        throw lastException ?? new InvalidOperationException("Function execution failed after retries");
    }

    public CancellationTokenSource CreateTimeoutToken(ValidationOptions? options = null, CancellationToken parentToken = default)
    {
        var timeoutSeconds = options?.TimeoutSeconds ?? DefaultTimeoutSeconds;
        var timeout = TimeSpan.FromSeconds(timeoutSeconds);

        var cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        cts.CancelAfter(timeout);

        _logger.LogDebug("Created timeout token with {TimeoutSeconds}s timeout", timeoutSeconds);
        return cts;
    }

    public Task<ResourceUtilizationMetrics> GetResourceMetricsAsync()
    {
        lock (_metricsLock)
        {
            var recentRequestTimes = GetRecentRequestTimes();
            var averageResponseTime = CalculateAverageResponseTime(recentRequestTimes);

            var metrics = new ResourceUtilizationMetrics
            {
                ActiveRequests = _activeRequests,
                QueuedRequests = 0, // This would require additional tracking
                MaxConcurrentRequests = _concurrencyLimiter.CurrentCount + _activeRequests,
                AverageResponseTime = averageResponseTime,
                LastRequestTime = _lastRequestTime,
                TotalRequestsProcessed = _totalRequestsProcessed,
                FailedRequests = _failedRequests
            };

            return Task.FromResult(metrics);
        }
    }

    private SemaphoreSlim GetOrCreateSemaphore(string key, int maxCount)
    {
        return _namedSemaphores.GetOrAdd(key, k => new SemaphoreSlim(maxCount, maxCount));
    }

    private void CleanupOldRequestTimes()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-5); // Keep last 5 minutes
        while (_requestTimes.TryPeek(out var time) && time < cutoff)
        {
            _requestTimes.TryDequeue(out _);
        }
    }

    private List<DateTime> GetRecentRequestTimes()
    {
        var recent = new List<DateTime>();
        var cutoff = DateTime.UtcNow.AddMinutes(-1); // Last minute

        foreach (var time in _requestTimes)
        {
            if (time >= cutoff)
            {
                recent.Add(time);
            }
        }

        return recent;
    }

    private double CalculateAverageResponseTime(List<DateTime> requestTimes)
    {
        if (requestTimes.Count < 2)
        {
            return 0.0;
        }

        var intervals = new List<double>();
        for (int i = 1; i < requestTimes.Count; i++)
        {
            intervals.Add((requestTimes[i] - requestTimes[i - 1]).TotalMilliseconds);
        }

        return intervals.Average();
    }

    private static bool IsRetriableException(Exception ex)
    {
        return ex switch
        {
            HttpRequestException => true,
            TaskCanceledException tce when !tce.CancellationToken.IsCancellationRequested => true, // Timeout
            SocketException => true,
            TimeoutException => true,
            InvalidOperationException when ex.Message.Contains("timeout") => true,
            _ => false
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _logger.LogDebug("Disposing RequestProcessingService");

        _concurrencyLimiter?.Dispose();

        foreach (var semaphore in _namedSemaphores.Values)
        {
            semaphore?.Dispose();
        }

        _namedSemaphores.Clear();
        _disposed = true;
    }
}

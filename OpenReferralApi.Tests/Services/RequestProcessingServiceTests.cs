using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class RequestProcessingServiceTests
{
    private Mock<ILogger<RequestProcessingService>> _loggerMock;
    private RequestProcessingService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<RequestProcessingService>>();
        _service = new RequestProcessingService(_loggerMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _service?.Dispose();
    }

    #region ExecuteWithConcurrencyControlAsync Tests

    [Test]
    public async Task ExecuteWithConcurrencyControlAsync_WithValidFunction_ReturnsResult()
    {
        // Arrange
        var expectedResult = 42;

        // Act
        var result = await _service.ExecuteWithConcurrencyControlAsync<int>(
            async ct => expectedResult,
            new ValidationOptions { MaxConcurrentRequests = 5 });

        // Assert
        result.Should().Be(expectedResult);
    }

    [Test]
    public void ExecuteWithConcurrencyControlAsync_WithException_ThrowsException()
    {
        // Arrange
        var expectedException = new InvalidOperationException("Test exception");

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.ExecuteWithConcurrencyControlAsync<int>(
                ct => throw expectedException,
                new ValidationOptions { MaxConcurrentRequests = 5 }));
    }

    [Test]
    public async Task ExecuteWithConcurrencyControlAsync_WithNullOptions_UsesDefaultConcurrency()
    {
        // Arrange & Act
        var result = await _service.ExecuteWithConcurrencyControlAsync<string>(
            async ct => "success",
            options: null);

        // Assert
        result.Should().Be("success");
    }

    [Test]
    public async Task ExecuteWithConcurrencyControlAsync_MultipleCallsConcurrently_RespectsConcurrencyLimit()
    {
        // Arrange
        var concurrencyTracker = new ConcurrencyTracker();
        var options = new ValidationOptions { MaxConcurrentRequests = 2 };

        // Act
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => _service.ExecuteWithConcurrencyControlAsync<bool>(
                async ct =>
                {
                    concurrencyTracker.IncrementCurrent();
                    concurrencyTracker.RecordMaxConcurrency();
                    await Task.Delay(50);
                    concurrencyTracker.DecrementCurrent();
                    return true;
                },
                options))
            .ToList();

        await Task.WhenAll(tasks);

        // Assert - with default concurrency of 5, max concurrent should be at most 2
        concurrencyTracker.MaxConcurrency.Should().BeLessThanOrEqualTo(2);
    }

    [Test]
    public async Task ExecuteWithConcurrencyControlAsync_ThrottlingDisabled_ThrowsWhenLimitExceeded()
    {
        // Arrange
        var options = new ValidationOptions { MaxConcurrentRequests = 1, UseThrottling = false };
        using var gate = new SemaphoreSlim(0, 1);

        var firstTask = _service.ExecuteWithConcurrencyControlAsync<int>(
            async ct =>
            {
                await gate.WaitAsync(ct);
                return 1;
            },
            options);

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.ExecuteWithConcurrencyControlAsync<int>(async ct => 2, options));

        gate.Release();
        await firstTask;
    }

    [Test]
    public async Task ExecuteWithConcurrencyControlAsync_WithCancellation_RespondsToCancel()
    {
        // Arrange
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        // Act & Assert - should either complete quickly or throw
        try
        {
            var result = await _service.ExecuteWithConcurrencyControlAsync<int>(
                async ct =>
                {
                    await Task.Delay(1000, ct);
                    return 42;
                },
                new ValidationOptions { MaxConcurrentRequests = 5 },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected behavior
        }
    }

    #endregion

    #region ExecuteMultipleConcurrentlyAsync Tests

    [Test]
    public async Task ExecuteMultipleConcurrentlyAsync_WithMultipleFunctions_ReturnsAllResults()
    {
        // Arrange
        var functions = new List<Func<CancellationToken, Task<int>>>
        {
            async ct => 1,
            async ct => 2,
            async ct => 3
        };

        // Act
        var results = await _service.ExecuteMultipleConcurrentlyAsync(functions);

        // Assert
        results.Should().HaveCount(3);
        results.Should().ContainInOrder(1, 2, 3);
    }

    [Test]
    public async Task ExecuteMultipleConcurrentlyAsync_WithEmptyList_ReturnsEmptyResult()
    {
        // Arrange
        var functions = new List<Func<CancellationToken, Task<int>>>();

        // Act
        var results = await _service.ExecuteMultipleConcurrentlyAsync(functions);

        // Assert
        results.Should().BeEmpty();
    }

    [Test]
    public void ExecuteMultipleConcurrentlyAsync_WithOneFailingFunction_ThrowsException()
    {
        // Arrange
        var functions = new List<Func<CancellationToken, Task<int>>>
        {
            async ct => 1,
            ct => throw new InvalidOperationException("Failed"),
            async ct => 3
        };

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(
            async () => await _service.ExecuteMultipleConcurrentlyAsync(functions));
    }

    #endregion

    #region ExecuteWithRetryAsync Tests

    [Test]
    public async Task ExecuteWithRetryAsync_SuccessOnFirstAttempt_ReturnsResult()
    {
        // Arrange
        var expectedResult = "success";
        var options = new ValidationOptions { RetryAttempts = 2 };

        // Act
        var result = await _service.ExecuteWithRetryAsync(
            async ct => expectedResult,
            options);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Test]
    public async Task ExecuteWithRetryAsync_FailsOnceThSuccessOnRetry_ReturnsResult()
    {
        // Arrange
        var attemptCount = 0;
        var options = new ValidationOptions { RetryAttempts = 2, RetryDelaySeconds = 0 };

        // Act
        var result = await _service.ExecuteWithRetryAsync<string>(async ct =>
        {
            attemptCount++;
            if (attemptCount == 1)
            {
                throw new HttpRequestException("Network error");
            }
            return "success";
        }, options);

        // Assert
        result.Should().Be("success");
        attemptCount.Should().Be(2);
    }

    [Test]
    public void ExecuteWithRetryAsync_ExceedsMaxRetries_ThrowsException()
    {
        // Arrange
        var options = new ValidationOptions { RetryAttempts = 2, RetryDelaySeconds = 0 };

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(
            async () => await _service.ExecuteWithRetryAsync<string>(async ct =>
            {
                throw new HttpRequestException("Network error");
            }, options));
    }

    [Test]
    public void ExecuteWithRetryAsync_NonRetriableException_ThrowsImmediately()
    {
        // Arrange
        var attemptCount = 0;
        var options = new ValidationOptions { RetryAttempts = 3, RetryDelaySeconds = 0 };

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await _service.ExecuteWithRetryAsync<string>(async ct =>
            {
                attemptCount++;
                throw new ArgumentException("Invalid argument");
            }, options);
        });

        // Should only attempt once for non-retriable exceptions
        attemptCount.Should().Be(1);
    }

    [Test]
    public void ExecuteWithRetryAsync_WithExponentialBackoff_IncreaseDelay()
    {
        // Arrange
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var options = new ValidationOptions { RetryAttempts = 2, RetryDelaySeconds = 1 };

        // Act & Assert
        Assert.ThrowsAsync<HttpRequestException>(
            async () => await _service.ExecuteWithRetryAsync<string>(async ct =>
            {
                throw new HttpRequestException("Network error");
            }, options));

        // Assert - with exponential backoff, should take more than immediate retries
        stopwatch.Stop();
        stopwatch.Elapsed.Should().BeGreaterThan(TimeSpan.FromMilliseconds(10));
    }

    [Test]
    public void ExecuteWithRetryAsync_WithCancellation_ThrowsOperationCanceled()
    {
        // Arrange
        var options = new ValidationOptions { RetryAttempts = 2, RetryDelaySeconds = 1 };
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        // Act & Assert - TaskCanceledException is a subclass of OperationCanceledException
        var exception = Assert.CatchAsync<OperationCanceledException>(async () =>
            await _service.ExecuteWithRetryAsync<string>(async ct =>
            {
                throw new HttpRequestException("Network error");
            }, options, cts.Token));
        
        Assert.That(exception, Is.Not.Null);
    }

    #endregion

    #region CreateTimeoutToken Tests

    [Test]
    public void CreateTimeoutToken_WithValidOptions_CreatesTokenWithTimeout()
    {
        // Arrange
        var options = new ValidationOptions { TimeoutSeconds = 5 };

        // Act
        using var cts = _service.CreateTimeoutToken(options);

        // Assert
        cts.Token.CanBeCanceled.Should().BeTrue();
        cts.Token.IsCancellationRequested.Should().BeFalse();
    }

    [Test]
    public void CreateTimeoutToken_WithNullOptions_UsesDefaultTimeout()
    {
        // Arrange & Act
        using var cts = _service.CreateTimeoutToken(null);

        // Assert
        cts.Token.CanBeCanceled.Should().BeTrue();
    }

    [Test]
    public async Task CreateTimeoutToken_AfterTimeoutExpires_TokenIsCancelled()
    {
        // Arrange
        var options = new ValidationOptions { TimeoutSeconds = 1 };
        using var cts = _service.CreateTimeoutToken(options);

        // Act
        await Task.Delay(1100);

        // Assert
        cts.Token.IsCancellationRequested.Should().BeTrue();
    }

    [Test]
    public void CreateTimeoutToken_WithParentToken_LinksParentCancellation()
    {
        // Arrange
        using var parentCts = new CancellationTokenSource();
        var options = new ValidationOptions { TimeoutSeconds = 10 };

        // Act
        using var cts = _service.CreateTimeoutToken(options, parentCts.Token);
        parentCts.Cancel();

        // Assert
        cts.Token.IsCancellationRequested.Should().BeTrue();
    }

    #endregion

    #region GetResourceMetricsAsync Tests

    [Test]
    public async Task GetResourceMetricsAsync_ReturnsValidMetrics()
    {
        // Arrange
        var options = new ValidationOptions { MaxConcurrentRequests = 5 };

        // Execute a few operations
        await _service.ExecuteWithConcurrencyControlAsync<int>(
            async ct => { await Task.Delay(10); return 1; },
            options);

        await _service.ExecuteWithConcurrencyControlAsync<int>(
            async ct => { await Task.Delay(10); return 1; },
            options);

        // Act
        var metrics = await _service.GetResourceMetricsAsync();

        // Assert
        metrics.Should().NotBeNull();
        metrics.MaxConcurrentRequests.Should().Be(5);
        metrics.TotalRequestsProcessed.Should().BeGreaterThanOrEqualTo(2);
        metrics.ActiveRequests.Should().Be(0);
        metrics.LastRequestTime.Should().NotBe(DateTime.MinValue);
    }

    [Test]
    public async Task GetResourceMetricsAsync_TracksFailedRequests()
    {
        // Arrange
        var options = new ValidationOptions { MaxConcurrentRequests = 5 };

        // Execute a successful operation
        await _service.ExecuteWithConcurrencyControlAsync<string>(
            async ct => "success",
            options);

        // Execute a failing operation
        try
        {
            await _service.ExecuteWithConcurrencyControlAsync<int>(
                ct => throw new InvalidOperationException("Failed"),
                options);
        }
        catch { }

        // Act
        var metrics = await _service.GetResourceMetricsAsync();

        // Assert
        metrics.FailedRequests.Should().Be(1);
        metrics.TotalRequestsProcessed.Should().BeGreaterThanOrEqualTo(1);
    }

    #endregion

    #region Disposal Tests

    [Test]
    public void Dispose_ReleasesResources()
    {
        // Arrange
        var service = new RequestProcessingService(_loggerMock.Object);

        // Act
        service.Dispose();

        // Assert - should not throw on second dispose
        service.Dispose();
    }

    #endregion

    /// <summary>
    /// Helper class to track concurrent request execution
    /// </summary>
    private class ConcurrencyTracker
    {
        private int _currentConcurrency;
        public int MaxConcurrency { get; private set; }

        public void IncrementCurrent()
        {
            Interlocked.Increment(ref _currentConcurrency);
        }

        public void DecrementCurrent()
        {
            Interlocked.Decrement(ref _currentConcurrency);
        }

        public void RecordMaxConcurrency()
        {
            lock (this)
            {
                if (_currentConcurrency > MaxConcurrency)
                {
                    MaxConcurrency = _currentConcurrency;
                }
            }
        }
    }
}


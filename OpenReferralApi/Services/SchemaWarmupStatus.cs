namespace OpenReferralApi.Services;

public interface ISchemaWarmupStatusProvider
{
    SchemaWarmupStatusSnapshot GetSnapshot();
}

public interface ISchemaWarmupStatusTracker : ISchemaWarmupStatusProvider
{
    void MarkSkipped(string reason);
    void MarkStarted(int configuredUrlCount);
    void MarkSuccess();
    void MarkFailure(string schemaUrl);
    void MarkCompleted(bool cancelled);
}

public sealed class SchemaWarmupStatusSnapshot
{
    public string State { get; init; } = "not-started";
    public DateTimeOffset? LastStartedAtUtc { get; init; }
    public DateTimeOffset? LastCompletedAtUtc { get; init; }
    public int ConfiguredUrlCount { get; init; }
    public int AttemptedCount { get; init; }
    public int SucceededCount { get; init; }
    public int FailedCount { get; init; }
    public string? LastFailureUrl { get; init; }
    public string? SkipReason { get; init; }
}

public sealed class SchemaWarmupStatusTracker : ISchemaWarmupStatusTracker
{
    private readonly object _sync = new();
    private string _state = "not-started";
    private DateTimeOffset? _lastStartedAtUtc;
    private DateTimeOffset? _lastCompletedAtUtc;
    private int _configuredUrlCount;
    private int _attemptedCount;
    private int _succeededCount;
    private int _failedCount;
    private string? _lastFailureUrl;
    private string? _skipReason;

    public void MarkSkipped(string reason)
    {
        lock (_sync)
        {
            _state = "skipped";
            _skipReason = reason;
            _lastCompletedAtUtc = DateTimeOffset.UtcNow;
        }
    }

    public void MarkStarted(int configuredUrlCount)
    {
        lock (_sync)
        {
            _state = "running";
            _lastStartedAtUtc = DateTimeOffset.UtcNow;
            _configuredUrlCount = configuredUrlCount;
            _attemptedCount = 0;
            _succeededCount = 0;
            _failedCount = 0;
            _lastFailureUrl = null;
            _skipReason = null;
        }
    }

    public void MarkSuccess()
    {
        lock (_sync)
        {
            _attemptedCount++;
            _succeededCount++;
        }
    }

    public void MarkFailure(string schemaUrl)
    {
        lock (_sync)
        {
            _attemptedCount++;
            _failedCount++;
            _lastFailureUrl = schemaUrl;
        }
    }

    public void MarkCompleted(bool cancelled)
    {
        lock (_sync)
        {
            if (cancelled)
            {
                _state = "cancelled";
            }
            else if (_failedCount > 0)
            {
                _state = "completed-with-errors";
            }
            else
            {
                _state = "completed";
            }

            _lastCompletedAtUtc = DateTimeOffset.UtcNow;
        }
    }

    public SchemaWarmupStatusSnapshot GetSnapshot()
    {
        lock (_sync)
        {
            return new SchemaWarmupStatusSnapshot
            {
                State = _state,
                LastStartedAtUtc = _lastStartedAtUtc,
                LastCompletedAtUtc = _lastCompletedAtUtc,
                ConfiguredUrlCount = _configuredUrlCount,
                AttemptedCount = _attemptedCount,
                SucceededCount = _succeededCount,
                FailedCount = _failedCount,
                LastFailureUrl = _lastFailureUrl,
                SkipReason = _skipReason
            };
        }
    }
}

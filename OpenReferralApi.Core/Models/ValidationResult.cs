using System;
using System.Text.Json.Serialization;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Common interface for metadata objects
/// </summary>
public interface IMetadata
{
    DateTime Timestamp { get; set; }
}

/// <summary>
/// Base class for validation results containing common validation properties
/// </summary>
public abstract class ValidationResultBase
{
    [JsonPropertyName("isValid")]
    public bool IsValid { get; set; }

    [JsonPropertyName("errors")]
    public List<ValidationError> Errors { get; set; } = new();

}

public class ValidationResult : ValidationResultBase
{

    [JsonPropertyName("duration")]
    public TimeSpan Duration { get; set; }

    [JsonPropertyName("schemaVersion")]
    public string? SchemaVersion { get; set; }

    [JsonPropertyName("metadata")]
    public ValidationMetadata? Metadata { get; set; }
}

public class ValidationError
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("errorCode")]
    public string ErrorCode { get; set; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "Error";

    [JsonPropertyName("lineNumber")]
    public int? LineNumber { get; set; }

    [JsonPropertyName("columnNumber")]
    public int? ColumnNumber { get; set; }
}

public class ValidationMetadata : IMetadata
{
    [JsonPropertyName("schemaTitle")]
    public string? SchemaTitle { get; set; }

    [JsonPropertyName("schemaDescription")]
    public string? SchemaDescription { get; set; }

    [JsonPropertyName("dataSize")]
    public long DataSize { get; set; }

    [JsonPropertyName("validationTimestamp")]
    public DateTime ValidationTimestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Implements IMetadata.Timestamp
    /// </summary>
    [JsonIgnore]
    public DateTime Timestamp
    {
        get => ValidationTimestamp;
        set => ValidationTimestamp = value;
    }

    [JsonPropertyName("dataSource")]
    public string? DataSource { get; set; }
}


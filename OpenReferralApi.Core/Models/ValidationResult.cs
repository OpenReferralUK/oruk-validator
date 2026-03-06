using Newtonsoft.Json;

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
    [JsonProperty("isValid")]
    public bool IsValid { get; set; }

    [JsonProperty("errors")]
    public List<ValidationError> Errors { get; set; } = new();

}

public class ValidationResult : ValidationResultBase
{

    [JsonProperty("duration")]
    public TimeSpan Duration { get; set; }

    [JsonProperty("schemaVersion")]
    public string? SchemaVersion { get; set; }

    [JsonProperty("metadata")]
    public CommonValidationMetadata? Metadata { get; set; }
}

public class ValidationError
{
    [JsonProperty("path")]
    public string Path { get; set; } = string.Empty;

    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;

    [JsonProperty("errorCode")]
    public string ErrorCode { get; set; } = string.Empty;

    [JsonProperty("severity")]
    public string Severity { get; set; } = "Error";

    [JsonProperty("lineNumber")]
    public int? LineNumber { get; set; }

    [JsonProperty("columnNumber")]
    public int? ColumnNumber { get; set; }
}



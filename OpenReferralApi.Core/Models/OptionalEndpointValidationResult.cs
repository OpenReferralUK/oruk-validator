using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Result of validating an optional endpoint response
/// </summary>
public class OptionalEndpointValidationResult
{
    [JsonProperty("isOptional")]
    public bool IsOptional { get; set; }

    [JsonProperty("validationStatus")]
    public OptionalEndpointStatus ValidationStatus { get; set; }

    [JsonProperty("statusCode")]
    public int StatusCode { get; set; }

    [JsonProperty("category")]
    public string? Category { get; set; }

    [JsonProperty("isValid")]
    public bool IsValid { get; set; }

    [JsonProperty("requiresSchemaValidation")]
    public bool RequiresSchemaValidation { get; set; }

    [JsonProperty("message")]
    public string Message { get; set; } = string.Empty;
}

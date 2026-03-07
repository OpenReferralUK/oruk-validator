using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Consolidated metadata model shared across JSON schema and OpenAPI validation flows.
/// </summary>
public class CommonValidationMetadata : IMetadata
{
    [JsonProperty("openApiVersion")]
    public string? OpenApiVersion { get; set; }

    [JsonProperty("title")]
    public string? Title { get; set; }

    [JsonProperty("version")]
    public string? Version { get; set; }

    [JsonProperty("baseUrl")]
    public string? BaseUrl { get; set; }

    [JsonProperty("testTimestamp")]
    public DateTime? TestTimestamp { get; set; }

    [JsonProperty("testDuration")]
    public TimeSpan? TestDuration { get; set; }

    [JsonProperty("userAgent")]
    public string? UserAgent { get; set; }

    internal string? ProfileReason { get; set; }

    [JsonProperty("schemaTitle")]
    public string? SchemaTitle { get; set; }

    [JsonProperty("schemaDescription")]
    public string? SchemaDescription { get; set; }

    [JsonProperty("dataSize")]
    public long? DataSize { get; set; }

    [JsonProperty("validationTimestamp")]
    public DateTime? ValidationTimestamp { get; set; }

    [JsonProperty("dataSource")]
    public string? DataSource { get; set; }

    [JsonIgnore]
    public DateTime Timestamp
    {
        get => TestTimestamp ?? ValidationTimestamp ?? DateTime.UtcNow;
        set
        {
            if (TestTimestamp.HasValue || !ValidationTimestamp.HasValue)
            {
                TestTimestamp = value;
                return;
            }

            ValidationTimestamp = value;
        }
    }
}
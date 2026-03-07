using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents authentication credentials and configuration for accessing the API server during endpoint testing
/// </summary>
public class DataSourceAuthentication : IAuthenticationConfig
{
    [DefaultValue("")]
    [JsonProperty("apiKey")]
    public string? ApiKey { get; set; }

    [DefaultValue("X-API-Key")]
    [JsonProperty("apiKeyHeader")]
    public string ApiKeyHeader { get; set; } = "X-API-Key";

    [DefaultValue("")]
    [JsonProperty("bearerToken")]
    public string? BearerToken { get; set; }

    [JsonProperty("basicAuth")]
    public BasicAuthentication? BasicAuth { get; set; }

    [JsonProperty("customHeaders")]
    public Dictionary<string, string>? CustomHeaders { get; set; } = new();
}

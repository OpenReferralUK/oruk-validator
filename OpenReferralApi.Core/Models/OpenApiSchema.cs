using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration for OpenAPI schema location and authentication
/// </summary>
public class OpenApiSchema
{
    /// <summary>
    /// URL to fetch the OpenAPI specification from (JSON or YAML)
    /// The service will download and parse the specification from this URL
    /// Supports HTTP/HTTPS URLs and handles $ref resolution for external references
    /// </summary>
    [JsonProperty("url")]
    public string? Url { get; set; }

    /// <summary>
    /// Authentication credentials and configuration for accessing the OpenAPI schema URL
    /// Used when fetching the OpenAPI specification requires authentication
    /// Supports API keys, bearer tokens, basic auth, and custom headers
    /// If null, schema fetching will be attempted without authentication
    /// </summary>
    [JsonProperty("authentication")]
    public DataSourceAuthentication? Authentication { get; set; }
}

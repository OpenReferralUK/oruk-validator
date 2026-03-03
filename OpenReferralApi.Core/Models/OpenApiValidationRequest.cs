using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Request model for initiating OpenAPI specification validation and testing
/// Contains all necessary information to validate specs and optionally test live endpoints
/// </summary>
public class OpenApiValidationRequest
{

    /// <summary>
    /// OpenAPI schema configuration including URL and optional authentication
    /// Used to fetch and authenticate access to the OpenAPI specification
    /// If null, the schema URL will be discovered from the baseUrl
    /// </summary>
    [JsonProperty("openApiSchema")]
    public OpenApiSchema? OpenApiSchema { get; set; }

    /// <summary>
    /// Base URL of the live API server for endpoint testing
    /// Required if endpoint testing is enabled in options
    /// Should include protocol (http/https) and may include port (e.g., "https://api.example.com:8080")
    /// </summary>
    [JsonProperty("baseUrl")]
    public string? BaseUrl { get; set; }

    /// <summary>
    /// Authentication credentials and configuration for accessing the API server during endpoint testing
    /// Supports API keys, bearer tokens, basic auth, and custom headers
    /// Required if endpoint testing is enabled and the API requires authentication for access
    /// </summary>
    [JsonProperty("dataSourceAuth")]
    public DataSourceAuthentication? DataSourceAuth { get; set; }

    /// <summary>
    /// Configuration options controlling validation behavior and endpoint testing
    /// Determines what types of validation and testing to perform
    /// If null, default options will be used (specification validation only)
    /// </summary>
    [JsonProperty("options")]
    public OpenApiValidationOptions? Options { get; set; }

    /// <summary>
    /// Internal property to pass the profile discovery reason from discovery to validation.
    /// This is not part of the public API request and should not be set by clients.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string? ProfileReason { get; set; }
}

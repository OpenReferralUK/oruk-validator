using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json.Nodes;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

public interface IOpenApiDiscoveryService
{
    /// <summary>
    /// Attempts to discover an OpenAPI schema URL from the provided base URL.
    /// Returns the discovered URL and the reason for how it was discovered, or null if none found.
    /// </summary>
    Task<(string? url, string? reason)> DiscoverOpenApiUrlAsync(string baseUrl, CancellationToken cancellationToken = default);
}

public class OpenApiDiscoveryService : IOpenApiDiscoveryService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OpenApiDiscoveryService> _logger;
    private readonly string _baseSpecificationUrl;

    public OpenApiDiscoveryService(IHttpClientFactory httpClientFactory, ILogger<OpenApiDiscoveryService> logger, IOptions<SpecificationOptions> specificationOptions)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _baseSpecificationUrl = specificationOptions.Value.BaseUrl;
    }

    public async Task<(string? url, string? reason)> DiscoverOpenApiUrlAsync(string baseUrl, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return (null, null);

        const float defaultSpecificationVersion = 1.0f;
        var defaultSpec = $"{_baseSpecificationUrl}{defaultSpecificationVersion:0.0}/openapi.json";
        try
        {
            using var httpClient = _httpClientFactory?.CreateClient("OpenApiValidationService") ?? new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10);
            _logger.LogInformation("Requesting BaseUrl to discover openapi_url: {BaseUrl}", baseUrl);
            var resp = await httpClient.GetAsync(baseUrl, cancellationToken);
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogInformation("BaseUrl request returned {Status}; defaulting to HSDS-UK 1.0 spec: {DefaultSpec}", resp.StatusCode, defaultSpec);
                return (defaultSpec, "Defaulted to HSDS-UK 1.0 (base URL request failed)");
            }

            var content = await resp.Content.ReadAsStringAsync(cancellationToken);
            try
            {
                var j = JsonNode.Parse(content);
                if (j == null)
                {
                    _logger.LogInformation("Failed to parse JSON from BaseUrl response; defaulting to HSDS-UK 1.0 spec: {DefaultSpec}", defaultSpec);
                    return (defaultSpec, "Defaulted to HSDS-UK 1.0 (failed to parse base URL response)");
                }

                // Check for version field and construct URL
                var versionNode = j["version"];
                var version = versionNode?.GetValue<string>();
                if (!string.IsNullOrEmpty(version))
                {
                    var extractedVersion = ExtractVersionNumber(version);
                    if (extractedVersion.HasValue)
                    {
                        var versionedSpec = $"{_baseSpecificationUrl}{extractedVersion.Value:0.0}/openapi.json";
                        _logger.LogInformation("Detected version '{Version}'; using HSDS-UK {ExtractedVersion:0.0} spec: {OpenApiUrl}", version, extractedVersion.Value, versionedSpec);
                        return (versionedSpec, $"Standard version {version} read from '/' endpoint");
                    }
                }

                // Check for explicit openapi_url field first
                var openapiUrl = j["openapi_url"]?.GetValue<string>()
                    ?? j["openapiUrl"]?.GetValue<string>()
                    ?? j["open_api_url"]?.GetValue<string>();
                
                if (!string.IsNullOrEmpty(openapiUrl))
                {
                    _logger.LogInformation("Discovered openapi_url: {OpenApiUrl}", openapiUrl);
                    return (openapiUrl, "OpenAPI URL read from '/' endpoint (openapi_url field)");
                }

                _logger.LogInformation("No openapi_url or version in BaseUrl response; defaulting to HSDS-UK 1.0 spec: {DefaultSpec}", defaultSpec);
                return (defaultSpec, "Defaulted to HSDS-UK 1.0 (no version or openapi_url found)");
            }
            catch (Exception jex)
            {
                _logger.LogWarning(jex, "Failed to parse JSON from BaseUrl response; defaulting to HSDS-UK 1.0 spec: {DefaultSpec}", defaultSpec);
                return (defaultSpec, "Defaulted to HSDS-UK 1.0 (failed to parse base URL response)");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error requesting BaseUrl to discover openapi_url; defaulting to HSDS-UK 1.0 spec: {DefaultSpec}", defaultSpec);
            return (defaultSpec, "Defaulted to HSDS-UK 1.0 (error requesting base URL)");
        }
    }

    private static float? ExtractVersionNumber(string version)
    {
        // Try to extract version number from formats like "HSDS-UK-3.0", "V3", "3.0", "3.1", etc.
        var versionString = version
            .Replace("HSDS-UK-", "", StringComparison.OrdinalIgnoreCase)
            .Replace("V", "", StringComparison.OrdinalIgnoreCase)
            .Replace("v", "")
            .Trim();

        if (float.TryParse(versionString, out var versionNumber))
        {
            return versionNumber;
        }

        return null;
    }
}

using System.Net;
using Microsoft.Extensions.Logging;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for parsing and validating URIs and URLs consistently across the application
/// </summary>
public interface IPathParsingService
{
    /// <summary>
    /// Validates and normalizes a URI string
    /// </summary>
    /// <param name="uriString">The URI string to validate</param>
    /// <param name="options">Validation options</param>
    /// <returns>Parsed and validated URI</returns>
    /// <exception cref="ArgumentException">Thrown when URI is invalid</exception>
    Task<Uri> ValidateAndParseUriAsync(string uriString, ValidationOptions? options = null);

    /// <summary>
    /// Validates and normalizes a URL string for data fetching
    /// </summary>
    /// <param name="urlString">The URL string to validate</param>
    /// <param name="options">Validation options</param>
    /// <returns>Parsed and validated URI suitable for HTTP requests</returns>
    /// <exception cref="ArgumentException">Thrown when URL is invalid</exception>
    Task<Uri> ValidateAndParseDataUrlAsync(string urlString, ValidationOptions? options = null);

    /// <summary>
    /// Validates and normalizes a schema URI string
    /// </summary>
    /// <param name="schemaUri">The schema URI string to validate</param>
    /// <param name="options">Validation options</param>
    /// <returns>Parsed and validated URI for schema loading</returns>
    /// <exception cref="ArgumentException">Thrown when schema URI is invalid</exception>
    Task<Uri> ValidateAndParseSchemaUriAsync(string schemaUri, ValidationOptions? options = null);

    /// <summary>
    /// Checks if a URI is accessible and returns additional metadata
    /// </summary>
    /// <param name="uri">The URI to check</param>
    /// <param name="options">Validation options</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>URI accessibility information</returns>
    Task<UriAccessibilityResult> CheckUriAccessibilityAsync(Uri uri, ValidationOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves relative URIs against a base URI
    /// </summary>
    /// <param name="baseUrl">The base URI</param>
    /// <param name="relativeUri">The relative URI to resolve</param>
    /// <returns>Resolved absolute URI</returns>
    Uri ResolveRelativeUri(Uri baseUrl, string relativeUri);
}

/// <summary>
/// Result of URI accessibility check
/// </summary>
public class UriAccessibilityResult
{
    public bool IsAccessible { get; set; }
    public string? ContentType { get; set; }
    public long? ContentLength { get; set; }
    public DateTime? LastModified { get; set; }
    public string? ErrorMessage { get; set; }
    public int StatusCode { get; set; }
}

/// <summary>
/// Service for parsing and validating URIs and URLs consistently across the application
/// </summary>
public class PathParsingService : IPathParsingService
{
    private readonly ILogger<PathParsingService> _logger;
    private readonly HttpClient _httpClient;

    private static readonly string[] AllowedSchemes = { "http", "https", "ftp", "ftps" };
    private static readonly string[] DataUrlSchemes = { "http", "https" };
    private static readonly string[] SchemaUriSchemes = { "http", "https", "file" };

    public PathParsingService(ILogger<PathParsingService> logger, HttpClient httpClient)
    {
        _logger = logger;
        _httpClient = httpClient;
    }

    public Task<Uri> ValidateAndParseUriAsync(string uriString, ValidationOptions? options = null)
    {
        return ValidateAndParseUriInternalAsync(uriString, AllowedSchemes, "URI", options);
    }

    public Task<Uri> ValidateAndParseDataUrlAsync(string urlString, ValidationOptions? options = null)
    {
        return ValidateAndParseUriInternalAsync(urlString, DataUrlSchemes, "Data URL", options);
    }

    public Task<Uri> ValidateAndParseSchemaUriAsync(string schemaUri, ValidationOptions? options = null)
    {
        return ValidateAndParseUriInternalAsync(schemaUri, SchemaUriSchemes, "Schema URI", options);
    }

    public async Task<UriAccessibilityResult> CheckUriAccessibilityAsync(Uri uri, ValidationOptions? options = null, CancellationToken cancellationToken = default)
    {
        var result = new UriAccessibilityResult();

        try
        {
            _logger.LogDebug("Checking accessibility of URI: {Uri}", uri);

            if (uri.Scheme == "file")
            {
                // Handle file URIs
                var filePath = uri.LocalPath;
                result.IsAccessible = File.Exists(filePath);
                result.StatusCode = result.IsAccessible ? 200 : 404;

                if (result.IsAccessible)
                {
                    var fileInfo = new FileInfo(filePath);
                    result.ContentLength = fileInfo.Length;
                    result.LastModified = fileInfo.LastWriteTimeUtc;
                    result.ContentType = GetContentTypeFromExtension(fileInfo.Extension);
                }
                else
                {
                    result.ErrorMessage = "File not found";
                }
            }
            else if (uri.Scheme == "http" || uri.Scheme == "https")
            {
                // Handle HTTP/HTTPS URIs
                var timeout = TimeSpan.FromSeconds(options?.TimeoutSeconds ?? 30);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeout);

                using var request = new HttpRequestMessage(HttpMethod.Head, uri);
                ConfigureHttpRequest(request, options);

                try
                {
                    using var response = await _httpClient.SendAsync(request, cts.Token);

                    result.IsAccessible = response.IsSuccessStatusCode;
                    result.StatusCode = (int)response.StatusCode;
                    result.ContentType = response.Content.Headers.ContentType?.ToString();
                    result.ContentLength = response.Content.Headers.ContentLength;
                    result.LastModified = response.Content.Headers.LastModified?.UtcDateTime;

                    if (!response.IsSuccessStatusCode)
                    {
                        result.ErrorMessage = $"HTTP {response.StatusCode}: {response.ReasonPhrase}";
                    }
                }
                catch (HttpRequestException ex)
                {
                    result.IsAccessible = false;
                    result.StatusCode = 0;
                    result.ErrorMessage = ex.Message;
                    _logger.LogWarning(ex, "HTTP request failed for URI: {Uri}", uri);
                }
                catch (TaskCanceledException ex) when (ex.CancellationToken.IsCancellationRequested)
                {
                    result.IsAccessible = false;
                    result.StatusCode = 408; // Request Timeout
                    result.ErrorMessage = "Request timeout";
                    _logger.LogWarning("Request timeout for URI: {Uri}", uri);
                }
            }
            else
            {
                // Handle other schemes (FTP, etc.)
                result.IsAccessible = false;
                result.StatusCode = 0;
                result.ErrorMessage = $"Unsupported scheme for accessibility check: {uri.Scheme}";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking accessibility of URI: {Uri}", uri);
            result.IsAccessible = false;
            result.StatusCode = 0;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    public Uri ResolveRelativeUri(Uri baseUrl, string relativeUri)
    {
        try
        {
            if (string.IsNullOrEmpty(relativeUri))
            {
                throw new ArgumentException("Relative URI cannot be null or empty", nameof(relativeUri));
            }

            if (baseUrl == null)
            {
                throw new ArgumentNullException(nameof(baseUrl));
            }

            // Check if relativeUri is actually absolute
            if (Uri.IsWellFormedUriString(relativeUri, UriKind.Absolute))
            {
                return new Uri(relativeUri);
            }

            // Resolve relative URI
            return new Uri(baseUrl, relativeUri);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resolving relative URI '{RelativeUri}' against base '{baseUrl}'", relativeUri, baseUrl);
            throw new ArgumentException($"Failed to resolve relative URI '{relativeUri}' against base '{baseUrl}': {ex.Message}", ex);
        }
    }

    private async Task<Uri> ValidateAndParseUriInternalAsync(string uriString, string[] allowedSchemes, string uriType, ValidationOptions? options)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(uriString))
            {
                throw new ArgumentException($"{uriType} cannot be null or empty", nameof(uriString));
            }

            _logger.LogDebug("Validating {UriType}: {Uri}", uriType, uriString);

            // Basic URI validation
            if (!Uri.IsWellFormedUriString(uriString, UriKind.Absolute))
            {
                throw new ArgumentException($"Invalid {uriType.ToLower()}: {uriString}");
            }

            var uri = new Uri(uriString);

            // Scheme validation
            if (!allowedSchemes.Contains(uri.Scheme.ToLowerInvariant()))
            {
                throw new ArgumentException($"{uriType} scheme '{uri.Scheme}' is not supported. Allowed schemes: {string.Join(", ", allowedSchemes)}");
            }

            // Additional validation based on options
            if (options != null)
            {
                await ValidateUriWithOptionsAsync(uri, uriType, options);
            }

            // Security validation
            ValidateUriSecurity(uri, uriType, options);

            _logger.LogDebug("Successfully validated {UriType}: {Uri}", uriType, uri);
            return uri;
        }
        catch (UriFormatException ex)
        {
            _logger.LogError(ex, "URI format error for {UriType}: {Uri}", uriType, uriString);
            throw new ArgumentException($"Invalid {uriType.ToLower()} format: {uriString}", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating {UriType}: {Uri}", uriType, uriString);
            throw;
        }
    }

    private async Task ValidateUriWithOptionsAsync(Uri uri, string uriType, ValidationOptions options)
    {
        // SSL certificate validation
        if (uri.Scheme == "https" && options.ValidateSslCertificate)
        {
            // This would be implemented with actual SSL certificate validation
            _logger.LogDebug("SSL certificate validation enabled for {UriType}: {Uri}", uriType, uri);
        }

        // Accessibility check if required
        if (uri.Scheme == "http" || uri.Scheme == "https")
        {
            // Optional: Check if URI is accessible (can be disabled for performance)
            // This could be made configurable via options
        }

        await Task.CompletedTask; // Placeholder for async operations
    }

    private void ValidateUriSecurity(Uri uri, string uriType, ValidationOptions? options)
    {
        // Prevent localhost/private IP access unless explicitly allowed
        if (IsPrivateOrLocalhost(uri))
        {
            _logger.LogWarning("Potentially unsafe {UriType} accessing private/localhost: {Uri}", uriType, uri);
            // Could throw exception here based on security policy
        }

        // Validate port ranges
        if (uri.Port > 0 && !IsAllowedPort(uri.Port))
        {
            throw new ArgumentException($"{uriType} uses disallowed port: {uri.Port}");
        }
    }

    private void ConfigureHttpRequest(HttpRequestMessage request, ValidationOptions? options)
    {
        // Configure redirects
        if (options?.FollowRedirects == false)
        {
            // This would be handled at HttpClientHandler level
        }

        // Set User-Agent
        request.Headers.Add("User-Agent", "JsonValidator/1.0.0");

        // Set Accept headers for better compatibility
        request.Headers.Add("Accept", "application/json, application/schema+json, text/plain, */*");
    }

    private static bool IsPrivateOrLocalhost(Uri uri)
    {
        if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IPAddress.TryParse(uri.Host, out var ipAddress))
        {
            // Check for private IP ranges
            var bytes = ipAddress.GetAddressBytes();
            if (bytes.Length == 4) // IPv4
            {
                return (bytes[0] == 10) || // 10.0.0.0/8
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || // 172.16.0.0/12
                       (bytes[0] == 192 && bytes[1] == 168); // 192.168.0.0/16
            }
        }

        return false;
    }

    private static bool IsAllowedPort(int port)
    {
        // Allow standard HTTP/HTTPS ports and common service ports
        var allowedPorts = new[] { 80, 443, 8080, 8443, 3000, 5000, 8000, 9000 };
        return allowedPorts.Contains(port) || (port >= 1024 && port <= 65535);
    }

    private static string GetContentTypeFromExtension(string extension)
    {
        return extension.ToLowerInvariant() switch
        {
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".txt" => "text/plain",
            ".html" => "text/html",
            ".css" => "text/css",
            ".js" => "application/javascript",
            _ => "application/octet-stream"
        };
    }
}

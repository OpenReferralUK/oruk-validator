using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Internal helper class for loading remote JSON schemas with caching and authentication support.
/// </summary>
internal class RemoteSchemaLoader
{
    private static readonly HashSet<string> KnownJsonSchemaUrls = new(StringComparer.OrdinalIgnoreCase)
    {
        "https://json-schema.org/draft/2020-12/schema",
        "https://json-schema.org/draft/2020-12/meta/core",
        "https://json-schema.org/draft/2020-12/meta/applicator",
        "https://json-schema.org/draft/2020-12/meta/unevaluated",
        "https://json-schema.org/draft/2020-12/meta/validation",
        "https://json-schema.org/draft/2020-12/meta/meta-data",
        "https://json-schema.org/draft/2020-12/meta/format-annotation",
        "https://json-schema.org/draft/2020-12/meta/content"
    };

    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly IMemoryCache _memoryCache;
    private readonly CacheOptions _cacheOptions;
    private readonly string? _localSpecificationBaseUrl;
    private IAuthenticationConfig? _auth;

    public RemoteSchemaLoader(
        HttpClient httpClient,
        ILogger logger,
        IMemoryCache memoryCache,
        IOptions<CacheOptions> cacheOptions,
        string? localSpecificationBaseUrl = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
        _cacheOptions = cacheOptions?.Value ?? throw new ArgumentNullException(nameof(cacheOptions));
        _localSpecificationBaseUrl = localSpecificationBaseUrl;
    }

    /// <summary>
    /// Sets the authentication configuration for this loader instance.
    /// </summary>
    public void SetAuthentication(IAuthenticationConfig? auth)
    {
        _auth = auth;
    }

    /// <summary>
    /// Loads a remote JSON schema from a URL with caching support.
    /// </summary>
    public async Task<JsonNode?> LoadRemoteSchemaAsync(string schemaUrl)
    {
        var normalizedKnownSchemaUrl = NormalizeKnownSchemaUrl(schemaUrl);

        // Rewrite URL if needed (e.g., redirect openreferraluk.org URLs to local server)
        var rewrittenUrl = normalizedKnownSchemaUrl ?? RewriteSchemaUrl(schemaUrl);
        
        // Check persistent cache first if caching is enabled
        if (_cacheOptions.Enabled)
        {
            var cacheKey = GenerateCacheKey(rewrittenUrl);
            if (_memoryCache.TryGetValue<string>(cacheKey, out var cachedContent) && cachedContent != null)
            {
                _logger.LogDebug("Retrieved schema from cache: {SchemaUrl}", SchemaResolverService.SanitizeUrlForLogging(rewrittenUrl));
                return JsonNode.Parse(cachedContent);
            }
        }

        try
        {
            // Validate URL before making HTTP request to prevent SSRF attacks
            if (!Uri.TryCreate(rewrittenUrl, UriKind.Absolute, out var schemaUri) ||
                (schemaUri.Scheme != Uri.UriSchemeHttp && schemaUri.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException($"Invalid schema URL: Only HTTP and HTTPS URLs are allowed", nameof(schemaUrl));
            }

            if (rewrittenUrl != schemaUrl)
            {
                _logger.LogDebug("Rewritten schema URL from {OriginalUrl} to {RewrittenUrl}", 
                    SchemaResolverService.SanitizeUrlForLogging(schemaUrl), 
                    SchemaResolverService.SanitizeUrlForLogging(rewrittenUrl));
            }

            _logger.LogDebug("Fetching remote schema: {SchemaUrl}", SchemaResolverService.SanitizeUrlForLogging(rewrittenUrl));

            using var request = new HttpRequestMessage(HttpMethod.Get, rewrittenUrl);

            // Apply authentication only if the configuration is considered valid
            if (_auth != null && IsValidAuthentication(_auth))
            {
                ApplyAuthentication(request, _auth);
            }

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();

            // Store in persistent cache if caching is enabled
            if (_cacheOptions.Enabled)
            {
                var cacheKey = GenerateCacheKey(rewrittenUrl);
                var cacheEntryOptions = new MemoryCacheEntryOptions
                {
                    Size = content.Length,
                    Priority = CacheItemPriority.Normal
                };

                // Configure expiration
                if (_cacheOptions.ExpirationMinutes > 0)
                {
                    if (_cacheOptions.UseSlidingExpiration)
                    {
                        cacheEntryOptions.SlidingExpiration = TimeSpan.FromMinutes(_cacheOptions.SlidingExpirationMinutes);
                        cacheEntryOptions.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_cacheOptions.ExpirationMinutes);
                    }
                    else
                    {
                        cacheEntryOptions.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_cacheOptions.ExpirationMinutes);
                    }
                }

                _memoryCache.Set(cacheKey, content, cacheEntryOptions);
                _logger.LogDebug("Cached schema: {SchemaUrl} (expires in {Minutes} minutes)",
                    SchemaResolverService.SanitizeUrlForLogging(rewrittenUrl), _cacheOptions.ExpirationMinutes);
            }

            return JsonNode.Parse(content);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch remote schema: {SchemaUrl}",
                SchemaResolverService.SanitizeUrlForLogging(schemaUrl));
            throw;
        }
    }

    /// <summary>
    /// Applies authentication credentials to an HTTP request.
    /// </summary>
    private void ApplyAuthentication(HttpRequestMessage request, IAuthenticationConfig auth)
    {
        // Validate authentication data early to prevent propagation of tainted values
        if (auth == null)
            return;

        // Apply API Key authentication
        if (!string.IsNullOrEmpty(auth.ApiKey) && !string.IsNullOrEmpty(auth.ApiKeyHeader))
        {
            // Validate header name before using it to prevent header injection
            if (!IsValidHeaderName(auth.ApiKeyHeader))
            {
                _logger.LogWarning("Invalid API key header name provided, skipping API key authentication");
                return;
            }
            request.Headers.Add(auth.ApiKeyHeader, auth.ApiKey);
            _logger.LogDebug("Applied API Key authentication");
        }

        // Apply Bearer Token authentication
        if (!string.IsNullOrEmpty(auth.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.BearerToken);
            _logger.LogDebug("Applied Bearer Token authentication");
        }

        // Apply Basic authentication
        if (auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username) && !string.IsNullOrEmpty(auth.BasicAuth.Password))
        {
            var credentials = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{auth.BasicAuth.Username}:{auth.BasicAuth.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            _logger.LogDebug("Applied Basic authentication");
        }

        // Apply custom headers
        if (auth.CustomHeaders != null)
        {
            foreach (var header in auth.CustomHeaders)
            {
                // Validate header name
                if (!IsValidHeaderName(header.Key))
                {
                    _logger.LogWarning("Invalid custom header name provided: {HeaderName}", header.Key);
                    continue;
                }
                request.Headers.Add(header.Key, header.Value);
                _logger.LogDebug("Applied custom header: {HeaderName}", header.Key);
            }
        }
    }

    /// <summary>
    /// Validates that authentication configuration is present and properly formed.
    /// </summary>
    private static bool IsValidAuthentication(IAuthenticationConfig? auth)
    {
        if (auth == null)
        {
            return false;
        }

        // Validate that at least one authentication method is configured
        var hasApiKey = !string.IsNullOrEmpty(auth.ApiKey) && !string.IsNullOrEmpty(auth.ApiKeyHeader);
        var hasBearerToken = !string.IsNullOrEmpty(auth.BearerToken);
        var hasBasicAuth = auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username);
        var hasCustomHeaders = auth.CustomHeaders != null && auth.CustomHeaders.Count > 0;

        return hasApiKey || hasBearerToken || hasBasicAuth || hasCustomHeaders;
    }

    /// <summary>
    /// Validates HTTP header names to prevent header injection attacks.
    /// </summary>
    private static bool IsValidHeaderName(string headerName)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            return false;
        }

        // Header names must not contain control characters or colons
        // RFC 7230 section 3.2: header-field = field-name ":" OWS field-value OWS
        return !headerName.Any(c => char.IsControl(c) || c == ':' || c == '\r' || c == '\n');
    }

    /// <summary>
    /// Generates a cache key for a schema URL.
    /// </summary>
    private static string GenerateCacheKey(string schemaUrl)
    {
        return $"schema:{schemaUrl}";
    }

    /// <summary>
    /// Rewrites a schema URL if it points to a known remote specification server
    /// and a local specification base URL is configured.
    /// This allows development environments to use local schema files instead of remote ones.
    /// </summary>
    /// <param name="schemaUrl">The original schema URL.</param>
    /// <returns>The rewritten URL or the original URL if no rewriting is needed.</returns>
    private string RewriteSchemaUrl(string schemaUrl)
    {
        if (string.IsNullOrWhiteSpace(_localSpecificationBaseUrl))
        {
            return schemaUrl;
        }

        // Rewrite openreferraluk.org URLs to use the local specification server
        const string remoteSpecificationBase = "https://openreferraluk.org/specifications/";
        
        if (schemaUrl.StartsWith(remoteSpecificationBase, StringComparison.OrdinalIgnoreCase))
        {
            var relativePath = schemaUrl.Substring(remoteSpecificationBase.Length);
            var localUrl = $"{_localSpecificationBaseUrl.TrimEnd('/')}/{relativePath}";
            return localUrl;
        }

        return schemaUrl;
    }

    private static string? NormalizeKnownSchemaUrl(string schemaUrl)
    {
        if (!Uri.TryCreate(schemaUrl, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var normalized = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        if (KnownJsonSchemaUrls.Contains(normalized))
        {
            return normalized;
        }

        return null;
    }
}

using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Internal helper class for fetching and parsing OpenAPI specifications from remote URLs.
/// Handles authentication and reference resolution.
/// </summary>
internal class OpenApiSpecFetcher
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly ISchemaResolverService _schemaResolverService;
    private readonly bool _allowUserSuppliedAuth;

    public OpenApiSpecFetcher(
        HttpClient httpClient,
        ILogger logger,
        ISchemaResolverService schemaResolverService,
        bool allowUserSuppliedAuth)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _schemaResolverService = schemaResolverService ?? throw new ArgumentNullException(nameof(schemaResolverService));
        _allowUserSuppliedAuth = allowUserSuppliedAuth;
    }

    /// <summary>
    /// Fetches and optionally resolves an OpenAPI specification from a URL.
    /// </summary>
    /// <param name="specUrl">The URL of the OpenAPI specification</param>
    /// <param name="auth">Optional authentication credentials</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <param name="resolveReferences">Whether to resolve $ref references (true by default)</param>
    /// <returns>The parsed OpenAPI specification as JObject</returns>
    public async Task<JObject> FetchOpenApiSpecFromUrlAsync(
        string specUrl,
        DataSourceAuthentication? auth,
        CancellationToken cancellationToken,
        bool resolveReferences = true)
    {
        try
        {
            var safeSpecUrl = SchemaResolverService.SanitizeUrlForLogging(specUrl);
            _logger.LogInformation("Fetching OpenAPI specification from URL: {SpecUrl}", safeSpecUrl);

            if (!Uri.IsWellFormedUriString(specUrl, UriKind.Absolute))
            {
                throw new ArgumentException($"Invalid OpenAPI spec URL: {safeSpecUrl}");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, specUrl);

            // Apply authentication only if it is allowed by server configuration and passes strict validation
            DataSourceAuthentication? validatedAuth = null;
            if (_allowUserSuppliedAuth)
            {
                validatedAuth = ValidateAuthentication(auth);
                if (validatedAuth != null)
                {
                    ApplyAuthentication(request, validatedAuth);
                }
            }
            else if (auth != null)
            {
                _logger.LogWarning(
                    "User-supplied authentication was provided but is disabled by server configuration. " +
                    "Skipping authentication headers for request to {SpecUrl}",
                    safeSpecUrl);
            }

            var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            // Only resolve references if requested (lazy evaluation)
            // This avoids expensive resolution when we're only validating spec structure
            // or when endpoints won't be tested
            if (resolveReferences)
            {
                var resolvedContent = await _schemaResolverService.ResolveAsync(content, specUrl, validatedAuth);
                return JObject.Parse(resolvedContent);
            }

            // Return unresolved document for spec validation or later lazy resolution
            return JObject.Parse(content);
        }
        catch (Exception ex)
        {
            var safeSpecUrl = SchemaResolverService.SanitizeUrlForLogging(specUrl);
            _logger.LogError(ex, "Failed to fetch OpenAPI specification from URL: {SpecUrl}", safeSpecUrl);
            throw new InvalidOperationException($"Failed to fetch OpenAPI specification from URL: {safeSpecUrl}", ex);
        }
    }

    /// <summary>
    /// Validates authentication configuration before use.
    /// Only returns a non-null value if the configuration passes strict validation.
    /// </summary>
    private static DataSourceAuthentication? ValidateAuthentication(DataSourceAuthentication? auth)
    {
        if (auth == null)
        {
            return null;
        }

        // Normalize simple string fields
        if (!string.IsNullOrWhiteSpace(auth.ApiKey))
        {
            auth.ApiKey = auth.ApiKey.Trim();
        }

        if (!string.IsNullOrWhiteSpace(auth.BearerToken))
        {
            auth.BearerToken = auth.BearerToken.Trim();
        }

        if (auth.BasicAuth != null)
        {
            if (!string.IsNullOrWhiteSpace(auth.BasicAuth.Username))
            {
                auth.BasicAuth.Username = auth.BasicAuth.Username.Trim();
            }

            if (!string.IsNullOrWhiteSpace(auth.BasicAuth.Password))
            {
                auth.BasicAuth.Password = auth.BasicAuth.Password.Trim();
            }
        }

        // Simple length limits to avoid abuse
        bool IsTooLong(string? value, int maxLength) =>
            !string.IsNullOrEmpty(value) && value.Length > maxLength;

        const int MaxTokenLength = 4096;
        if (IsTooLong(auth.ApiKey, MaxTokenLength) ||
            IsTooLong(auth.BearerToken, MaxTokenLength) ||
            (auth.BasicAuth != null &&
                (IsTooLong(auth.BasicAuth.Username, MaxTokenLength) ||
                 IsTooLong(auth.BasicAuth.Password, MaxTokenLength))))
        {
            // Reject unreasonably large auth values
            return null;
        }

        // Validate custom headers against a conservative allowlist
        var hasCustomHeaders = false;
        if (auth.CustomHeaders != null && auth.CustomHeaders.Count > 0)
        {
            var allowedHeaderNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Authorization",
                "X-API-Key",
                "X-Api-Key"
            };

            var sanitizedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var kvp in auth.CustomHeaders)
            {
                var name = kvp.Key?.Trim();
                var value = kvp.Value;

                if (string.IsNullOrWhiteSpace(name) || !allowedHeaderNames.Contains(name))
                {
                    // Reject any disallowed or malformed header
                    return null;
                }

                if (IsTooLong(value, MaxTokenLength))
                {
                    return null;
                }

                sanitizedHeaders[name] = value;
            }

            if (sanitizedHeaders.Count > 0)
            {
                auth.CustomHeaders = sanitizedHeaders;
                hasCustomHeaders = true;
            }
        }

        // Determine whether there is at least one valid authentication mechanism configured
        var hasApiKey = !string.IsNullOrEmpty(auth.ApiKey);
        var hasBearerToken = !string.IsNullOrEmpty(auth.BearerToken);
        var hasBasicAuth = auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username);

        if (hasApiKey || hasBearerToken || hasBasicAuth || hasCustomHeaders)
        {
            return auth;
        }

        return null;
    }

    /// <summary>
    /// Applies authentication credentials to an HTTP request.
    /// </summary>
    private void ApplyAuthentication(HttpRequestMessage request, IAuthenticationConfig auth)
    {
        // Apply API Key authentication
        if (!string.IsNullOrEmpty(auth.ApiKey))
        {
            request.Headers.Add(auth.ApiKeyHeader, auth.ApiKey);
            _logger.LogDebug("Applied API Key authentication with header: {Header}",
                SchemaResolverService.SanitizeStringForLogging(auth.ApiKeyHeader));
        }

        // Apply Bearer Token authentication
        if (!string.IsNullOrEmpty(auth.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.BearerToken);
            _logger.LogDebug("Applied Bearer Token authentication");
        }

        // Apply Basic authentication
        if (auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username))
        {
            var credentials = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{auth.BasicAuth.Username}:{auth.BasicAuth.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            _logger.LogDebug("Applied Basic authentication for user: {Username}",
                SchemaResolverService.SanitizeStringForLogging(auth.BasicAuth.Username));
        }

        // Apply custom headers
        if (auth.CustomHeaders != null)
        {
            foreach (var header in auth.CustomHeaders)
            {
                request.Headers.Add(header.Key, header.Value);
                _logger.LogDebug("Applied custom header: {HeaderName}",
                    SchemaResolverService.SanitizeStringForLogging(header.Key));
            }
        }
    }
}

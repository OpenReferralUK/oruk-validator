using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for resolving JSON Schema references ($ref) and creating schemas with proper resolution.
/// Uses System.Text.Json for reference resolution and Newtonsoft.Json.Schema for JSchema creation.
/// Handles both external URL references and internal JSON pointer references.
/// </summary>
public interface ISchemaResolverService
{
  // System.Text.Json based schema resolution methods
  /// <summary>
  /// Resolves all $ref references in the provided schema with a base URI context.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JSON string).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <param name="auth">Optional authentication for fetching remote schemas.</param>
  /// <returns>The fully resolved schema as a JSON string.</returns>
  Task<string> ResolveAsync(string schema, string? baseUri = null, DataSourceAuthentication? auth = null);

  /// <summary>
  /// Resolves all $ref references in the provided schema with a base URI context.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JsonNode).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <param name="auth">Optional authentication for fetching remote schemas.</param>
  /// <returns>The fully resolved schema as a JsonNode.</returns>
  Task<JsonNode?> ResolveAsync(JsonNode schema, string? baseUri = null, DataSourceAuthentication? auth = null);

  // Newtonsoft.Json.Schema based schema creation methods
  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution
  /// </summary>
  Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default);

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI
  /// </summary>
  Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, DataSourceAuthentication? auth = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Resolves JSON Schema references ($ref) in OpenAPI/OpenReferral specifications.
/// Handles both external URL references and internal JSON pointer references.
/// Detects and preserves circular references to prevent infinite loops.
/// Fetches remote schemas via HTTP/HTTPS.
/// </summary>
/// <remarks>
/// This is a C# port of the TypeScript SchemaResolver used in the OpenReferral UK website.
/// Compatible with .NET 10 and uses System.Text.Json for JSON manipulation.
/// </remarks>
public class SchemaResolverService : ISchemaResolverService
{
  private readonly HttpClient _httpClient;
  private readonly ILogger<SchemaResolverService> _logger;
  private readonly IMemoryCache _memoryCache;
  private readonly CacheOptions _cacheOptions;
  private readonly RemoteSchemaLoader _remoteSchemaLoader;
  private readonly ReferenceResolver _referenceResolver;

  /// <summary>
  /// Initializes a new instance of the SchemaResolver for remote schema resolution.
  /// </summary>
  /// <param name="httpClient">HTTP client for fetching remote schemas.</param>
  /// <param name="logger">Logger instance.</param>
  /// <param name="memoryCache">Memory cache for persistent schema caching.</param>
  /// <param name="cacheOptions">Cache configuration options.</param>
  public SchemaResolverService(
    HttpClient httpClient,
    ILogger<SchemaResolverService> logger,
    IMemoryCache memoryCache,
    IOptions<CacheOptions> cacheOptions)
  {
    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
    _cacheOptions = cacheOptions?.Value ?? throw new ArgumentNullException(nameof(cacheOptions));
    _remoteSchemaLoader = new RemoteSchemaLoader(httpClient, logger, memoryCache, cacheOptions);
    _referenceResolver = new ReferenceResolver(logger, _remoteSchemaLoader);
  }

  /// <summary>
  /// Resolves all $ref references in the provided schema.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JSON string).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <param name="auth">Optional authentication for fetching remote schemas.</param>
  /// <returns>The fully resolved schema as a JSON string.</returns>
  public async Task<string> ResolveAsync(string schema, string? baseUri = null, DataSourceAuthentication? auth = null)
  {
    var jsonNode = JsonNode.Parse(schema);
    if (jsonNode == null)
    {
      throw new ArgumentException("Invalid JSON schema", nameof(schema));
    }

    var resolved = await ResolveAsync(jsonNode, baseUri, auth);
    return resolved?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "null";
  }

  /// <summary>
  /// Resolves all $ref references in the provided schema.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JsonNode).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <param name="auth">Optional authentication for fetching remote schemas.</param>
  /// <returns>The fully resolved schema as a JsonNode.</returns>
  public async Task<JsonNode?> ResolveAsync(JsonNode schema, string? baseUri = null, DataSourceAuthentication? auth = null)
  {
    // Configure authentication for the remote loader
    var validatedAuth = IsValidAuthentication(auth) ? auth : null;
    _remoteSchemaLoader.SetAuthentication(validatedAuth);

    // Initialize the reference resolver for this resolution session
    _referenceResolver.Initialize(schema, baseUri);

    // Pass a new HashSet to track the current resolution path
    return await _referenceResolver.ResolveAllRefsAsync(schema, new HashSet<string>());
  }

  /// <summary>
  /// Determines whether the provided authentication configuration is considered valid for use.
  /// This adds a server-side gate so that user-controlled data does not directly drive whether
  /// sensitive authentication behavior is applied.
  /// </summary>
  /// <param name="auth">The authentication configuration supplied by the caller.</param>
  /// <returns>True if the configuration is valid and may be applied; otherwise, false.</returns>
  private static bool IsValidAuthentication([NotNullWhen(true)] DataSourceAuthentication? auth)
  {
    if (auth == null)
    {
      return false;
    }

    // NOTE: We avoid assuming unnamed properties on DataSourceAuthentication.
    // If this type exposes a scheme/value model, additional checks should be added here
    // to restrict allowed schemes and ensure required fields are non-empty.
    return true;
  }

  /// <summary>
  /// Sanitizes a string for safe logging by stripping control characters (including newlines)
  /// that could be used for log-forging attacks. This is a general-purpose method for 
  /// sanitizing arbitrary user-supplied strings.
  /// </summary>
  public static string SanitizeStringForLogging(string input)
  {
    if (string.IsNullOrEmpty(input))
      return string.Empty;

    // Remove control characters (including CR/LF) and restrict to a conservative set of printable characters
    // to prevent log forging or confusing log output.
    var sanitizedChars = input
      .Where(c =>
        // Exclude control characters
        !char.IsControl(c) &&
        // Allow basic printable ASCII range; adjust as needed if wider Unicode is desired
        c >= ' ' && c <= '~')
      .ToArray();

    var sanitized = new string(sanitizedChars);

    // Limit length to prevent log flooding
    const int maxLength = 500;
    if (sanitized.Length > maxLength)
    {
      sanitized = sanitized.Substring(0, maxLength) + "...(truncated)";
    }

    return sanitized;
  }

  /// <summary>
  /// Sanitizes a URL for safe logging by removing query parameters and fragments
  /// and stripping any control characters (including newlines) that could be used
  /// for log-forging attacks.
  /// </summary>
  public static string SanitizeUrlForLogging(string url)
  {
    if (string.IsNullOrEmpty(url))
      return string.Empty;

    // Normalize whitespace and strip control characters (including CR/LF) to prevent log forging
    var trimmed = url.Trim();
    // Allow only a conservative set of URL-safe printable characters; replace others with '?'
    var cleanedChars = trimmed
      .Where(c => !char.IsControl(c))
      .Select(c =>
      {
        // Unreserved and common reserved URL characters
        const string allowedPunctuation = "-._~:/?#[]@!$&'()*+,;=%";
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            allowedPunctuation.IndexOf(c) >= 0)
        {
          return c;
        }
        // Replace any unusual characters with a placeholder to keep logs safe and readable
        return '?';
      })
      .ToArray();
    var cleaned = new string(cleanedChars);

    // Optionally limit length to avoid log flooding/obfuscation with attacker-controlled data
    const int maxLength = 2048;
    if (cleaned.Length > maxLength)
    {
      cleaned = cleaned.Substring(0, maxLength) + "...(truncated)";
    }

    try
    {
      // Prefer to log without query string or fragment where possible
      if (Uri.TryCreate(cleaned, UriKind.Absolute, out var uri))
      {
        // Return URL without query string or fragment
        var sanitized = $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}";
        // Ensure no control characters are present in the final value
        return new string(sanitized.Where(c => !char.IsControl(c)).ToArray());
      }
      // For relative or non-absolute URLs, just remove query and fragment from the cleaned value
      var questionMarkIndex = cleaned.IndexOf('?');
      var hashIndex = cleaned.IndexOf('#');
      var endIndex = cleaned.Length;

      if (questionMarkIndex > 0)
        endIndex = Math.Min(endIndex, questionMarkIndex);
      if (hashIndex > 0)
        endIndex = Math.Min(endIndex, hashIndex);

      var withoutQueryOrFragment = cleaned[..endIndex];
      return new string(withoutQueryOrFragment.Where(c => !char.IsControl(c)).ToArray());
    }
    catch
    {
      // If parsing fails, return a safely truncated, control-character-free version
      var fallback = cleaned;
      const int fallbackMaxLength = 100;
      if (fallback.Length > fallbackMaxLength)
      {
        fallback = fallback[..fallbackMaxLength] + "...";
      }
      return new string(fallback.Where(c => !char.IsControl(c)).ToArray());
    }
  }

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution
  /// </summary>
  public async Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default)
  {
    return await CreateSchemaFromJsonAsync(schemaJson, null, null, cancellationToken);
  }

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI
  /// Uses System.Text.Json based resolution to pre-resolve all $ref before creating JSchema
  /// </summary>
  public async Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, DataSourceAuthentication? auth = null, CancellationToken cancellationToken = default)
  {
    try
    {
      _logger.LogDebug("Creating JSON schema from JSON string with resolver. DocumentUri: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");

      // Pre-resolve all external and internal references using System.Text.Json based resolution
      string resolvedSchemaJson = schemaJson;
      try
      {
        _logger.LogDebug("Pre-resolving all schema references with base URI: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");
        resolvedSchemaJson = await ResolveAsync(schemaJson, documentUri, auth);
        _logger.LogDebug("Successfully pre-resolved all schema references");
      }
      catch (Exception ex)
      {
        _logger.LogWarning(ex, "Failed to pre-resolve schema, continuing with original schema");
        // Continue with original schema if resolution fails
        resolvedSchemaJson = schemaJson;
      }

      // Create JSchema with the fully resolved schema (no more $ref to resolve)
      var resolver = new JSchemaUrlResolver();

      // Parse the schema with resolver settings
      using var reader = new JsonTextReader(new StringReader(resolvedSchemaJson));

      var settings = new JSchemaReaderSettings
      {
        Resolver = resolver
      };

      // Set base URI for any remaining reference resolution if provided
      if (!string.IsNullOrEmpty(documentUri))
      {
        _logger.LogDebug("Loading schema with base URI: {DocumentUri}", SanitizeUrlForLogging(documentUri));
        settings.BaseUri = new Uri(documentUri);
      }

      JSchema schema;
      try
      {
        schema = await Task.Run(() => JSchema.Parse(resolvedSchemaJson, settings), cancellationToken);
        _logger.LogDebug("Successfully created schema with reference resolution");
      }
      catch (Exception ex)
      {
        _logger.LogWarning(ex, "Failed to parse schema with resolver, attempting to parse without resolver. DocumentUri: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");
        try
        {
          // Fallback: parse without resolver
          schema = await Task.Run(() => JSchema.Parse(resolvedSchemaJson), cancellationToken);
          _logger.LogDebug("Successfully created schema without resolver");
        }
        catch (Exception fallbackEx)
        {
          _logger.LogError(fallbackEx, "Failed to parse schema even without resolver. DocumentUri: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");
          throw new InvalidOperationException("Unable to parse schema with or without resolver", fallbackEx);
        }
      }

      return schema;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to create JSON schema from JSON with resolver. DocumentUri: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");
      throw;
    }
  }
}


using System.Text.Json;
using System.Text.Json.Nodes;
using System.Linq;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Json.Schema;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for resolving JSON Schema references ($ref) and creating schemas with proper resolution.
/// Uses System.Text.Json for reference resolution and JsonSchema.Net for schema validation.
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

  // JsonSchema.Net based schema creation methods
  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution
  /// </summary>
  Task<JsonSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default);

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI
  /// </summary>
  Task<JsonSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, DataSourceAuthentication? auth = null, CancellationToken cancellationToken = default);
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
  private static readonly HashSet<string> NonSchemaKeywords = new(StringComparer.OrdinalIgnoreCase)
  {
    "name",
    "path",
    "datapackage_metadata",
    "constraints",
    "core",
    "tabular_required",
    "datapackage_type",
    "example",
    "page"
  };
  private readonly Dictionary<string, JsonNode?> _refCache = new();
  private readonly HttpClient _httpClient;
  private readonly ILogger<SchemaResolverService> _logger;
  private readonly IMemoryCache _memoryCache;
  private readonly CacheOptions _cacheOptions;
  private readonly IJsonSerializationOptionsProvider _jsonSerializationOptionsProvider;
  private JsonNode? _rootDocument;
  private string? _baseUri;
  private DataSourceAuthentication? _auth;

  /// <summary>
  /// Initializes a new instance of the SchemaResolver for remote schema resolution.
  /// </summary>
  /// <param name="httpClient">HTTP client for fetching remote schemas.</param>
  /// <param name="logger">Logger instance.</param>
  /// <param name="memoryCache">Memory cache for persistent schema caching.</param>
  /// <param name="cacheOptions">Cache configuration options.</param>
  /// <param name="jsonSerializationOptionsProvider">Provider for shared JsonSerializerOptions.</param>
  public SchemaResolverService(
    HttpClient httpClient,
    ILogger<SchemaResolverService> logger,
    IMemoryCache memoryCache,
    IOptions<CacheOptions> cacheOptions,
    IJsonSerializationOptionsProvider jsonSerializationOptionsProvider)
  {
    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
    _cacheOptions = cacheOptions?.Value ?? throw new ArgumentNullException(nameof(cacheOptions));
    _jsonSerializationOptionsProvider = jsonSerializationOptionsProvider ?? throw new ArgumentNullException(nameof(jsonSerializationOptionsProvider));
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
    return resolved?.ToJsonString(_jsonSerializationOptionsProvider.PrettyPrintOptions) ?? "null";
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
    // Reset state for each resolution
    _refCache.Clear();
    _rootDocument = schema;
    _baseUri = baseUri;
    _auth = auth;

    // Pass a new HashSet to track the current resolution path
    return await ResolveAllRefsAsync(schema, new HashSet<string>());
  }

  private async Task<JsonNode?> LoadRemoteSchemaAsync(string schemaUrl)
  {
    // Check persistent cache first if caching is enabled
    if (_cacheOptions.Enabled)
    {
      var cacheKey = GenerateCacheKey(schemaUrl);
      if (_memoryCache.TryGetValue<string>(cacheKey, out var cachedContent) && cachedContent != null)
      {
        _logger.LogDebug("Retrieved schema from cache: {SchemaUrl}", SanitizeUrlForLogging(schemaUrl));
        return JsonNode.Parse(cachedContent);
      }
    }

    try
    {
      _logger.LogDebug("Fetching remote schema: {SchemaUrl}", SanitizeUrlForLogging(schemaUrl));
      
      using var request = new HttpRequestMessage(HttpMethod.Get, schemaUrl);
      
      // Apply authentication if provided
      if (_auth != null)
      {
        ApplyAuthentication(request, _auth);
      }
      
      var response = await _httpClient.SendAsync(request);
      response.EnsureSuccessStatusCode();
      var content = await response.Content.ReadAsStringAsync();

      // Store in persistent cache if caching is enabled
      if (_cacheOptions.Enabled)
      {
        var cacheKey = GenerateCacheKey(schemaUrl);
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
        _logger.LogDebug("Cached schema: {SchemaUrl} (expires in {Minutes} minutes)", SanitizeUrlForLogging(schemaUrl), _cacheOptions.ExpirationMinutes);
      }

      return JsonNode.Parse(content);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to fetch remote schema: {SchemaUrl}", SanitizeUrlForLogging(schemaUrl));
      throw;
    }
  }

  private void ApplyAuthentication(HttpRequestMessage request, DataSourceAuthentication auth)
  {
    // Apply API Key authentication
    if (!string.IsNullOrEmpty(auth.ApiKey))
    {
      request.Headers.Add(auth.ApiKeyHeader, auth.ApiKey);
      _logger.LogDebug("Applied API Key authentication with header: {Header}", auth.ApiKeyHeader);
    }

    // Apply Bearer Token authentication
    if (!string.IsNullOrEmpty(auth.BearerToken))
    {
      request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", auth.BearerToken);
      _logger.LogDebug("Applied Bearer Token authentication");
    }

    // Apply Basic authentication
    if (auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username))
    {
      var credentials = Convert.ToBase64String(
        System.Text.Encoding.ASCII.GetBytes($"{auth.BasicAuth.Username}:{auth.BasicAuth.Password}"));
      request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
      _logger.LogDebug("Applied Basic authentication for user: {Username}", auth.BasicAuth.Username);
    }

    // Apply custom headers
    if (auth.CustomHeaders != null)
    {
      foreach (var header in auth.CustomHeaders)
      {
        request.Headers.Add(header.Key, header.Value);
        _logger.LogDebug("Applied custom header: {HeaderName}", header.Key);
      }
    }
  }

  private string ResolveSchemaUrl(string refUrl)
  {
    // If it's already an absolute URL, return it
    if (Uri.IsWellFormedUriString(refUrl, UriKind.Absolute))
    {
      return refUrl;
    }

    // If we have a base URI and the ref is relative, resolve it
    if (!string.IsNullOrEmpty(_baseUri))
    {
      var baseUri = new Uri(_baseUri);
      var resolvedUri = new Uri(baseUri, refUrl);
      return resolvedUri.AbsoluteUri;
    }

    // Return as-is if we can't resolve it
    return refUrl;
  }

  private bool IsExternalSchemaRef(string refUrl)
  {
    // Check if this is a reference to an external schema file (not internal #/ references)
    // Could be absolute URL or relative path ending in .json
    return !refUrl.StartsWith('#') &&
           (refUrl.Contains(".json") ||
            Uri.IsWellFormedUriString(refUrl, UriKind.Absolute) ||
            refUrl.Contains("/"));
  }

  private bool IsInternalRef(string refUrl)
  {
    // Check if this is an internal JSON pointer reference
    return refUrl.StartsWith("#/");
  }

  /// <summary>
  /// Generates a cache key for a schema URL
  /// </summary>
  private string GenerateCacheKey(string schemaUrl)
  {
    return $"schema:{schemaUrl}";
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

  private JsonNode? ResolveJsonPointer(string pointer)
  {
    if (_rootDocument == null)
    {
      return null;
    }

    // Remove leading '#/' and split path
    var pathSegments = pointer.Replace("#/", "").Split('/');

    JsonNode? current = _rootDocument;

    foreach (var segment in pathSegments)
    {
      // Decode URI-encoded segments
      var decodedSegment = Uri.UnescapeDataString(segment);

      if (current == null)
      {
        return null;
      }

      // Handle objects
      if (current is JsonObject jsonObject)
      {
        if (!jsonObject.TryGetPropertyValue(decodedSegment, out current))
        {
          return null;
        }
      }
      // Handle arrays
      else if (current is JsonArray jsonArray && int.TryParse(decodedSegment, out var index))
      {
        if (index < 0 || index >= jsonArray.Count)
        {
          return null;
        }
        current = jsonArray[index];
      }
      else
      {
        return null;
      }
    }

    return current;
  }

  private bool HasSelfReference(JsonNode? schema, string refPointer)
  {
    // Check if this specific schema directly references itself
    if (schema == null)
    {
      return false;
    }

    if (schema is JsonObject jsonObject)
    {
      // Check if this object has a $ref that matches refPointer
      if (jsonObject.TryGetPropertyValue("$ref", out var refValue) &&
          refValue?.GetValue<string>() == refPointer)
      {
        return true;
      }

      // Check all values in the object
      foreach (var kvp in jsonObject)
      {
        if (kvp.Value != null && HasSelfReference(kvp.Value, refPointer))
        {
          return true;
        }
      }
    }
    else if (schema is JsonArray jsonArray)
    {
      // Recursively check array items
      foreach (var item in jsonArray)
      {
        if (HasSelfReference(item, refPointer))
        {
          return true;
        }
      }
    }

    return false;
  }

  private async Task<JsonNode?> ResolveInternalRefAsync(string refPointer, HashSet<string> visitedRefs)
  {
    // Detect circular references BEFORE checking cache
    if (visitedRefs.Contains(refPointer))
    {
      _logger.LogWarning("Circular internal reference detected: {RefPointer}", refPointer);
      return JsonNode.Parse($"{{\"$ref\":\"{refPointer}\"}}");
    }

    // Check if we've already resolved this internal reference
    if (_refCache.TryGetValue(refPointer, out var cached))
    {
      return cached?.DeepClone();
    }

    var resolved = ResolveJsonPointer(refPointer);

    if (resolved == null)
    {
      _logger.LogWarning("Could not resolve internal reference: {RefPointer}", refPointer);
      return JsonNode.Parse($"{{\"$ref\":\"{refPointer}\"}}");
    }

    // Check if this schema references itself - if so, preserve the ref to avoid expansion
    if (HasSelfReference(resolved, refPointer))
    {
      _logger.LogDebug("Self-referencing schema detected: {RefPointer}", refPointer);
      return JsonNode.Parse($"{{\"$ref\":\"{refPointer}\"}}");
    }

    visitedRefs.Add(refPointer);

    // Recursively resolve any nested references
    var fullyResolved = await ResolveAllRefsAsync(resolved.DeepClone(), visitedRefs);

    // Cache the fully resolved schema
    _refCache[refPointer] = fullyResolved?.DeepClone();

    // Remove from visited - we're done with this resolution path
    visitedRefs.Remove(refPointer);

    return fullyResolved;
  }

  private async Task<JsonNode?> ResolveRefAsync(string refUrl, HashSet<string> visitedRefs)
  {
    // Resolve the URL (handle relative URLs)
    var resolvedUrl = ResolveSchemaUrl(refUrl);

    // Check if we've already loaded this schema
    if (_refCache.TryGetValue(resolvedUrl, out var cached))
    {
      return cached?.DeepClone();
    }

    // Detect circular references
    if (visitedRefs.Contains(resolvedUrl))
    {
      _logger.LogWarning("Circular reference detected: {ResolvedUrl}", SanitizeUrlForLogging(resolvedUrl));
      return JsonNode.Parse($"{{\"$ref\":\"{refUrl}\"}}");
    }

    visitedRefs.Add(resolvedUrl);

    try
    {
      var schema = await LoadRemoteSchemaAsync(resolvedUrl);

      // Cache the schema before resolving its refs to handle circular dependencies
      _refCache[resolvedUrl] = schema?.DeepClone();

      // Store the previous base URI and update it for nested resolution
      var previousBaseUri = _baseUri;
      _baseUri = resolvedUrl;

      // Recursively resolve all $ref in this schema
      var resolved = await ResolveAllRefsAsync(schema?.DeepClone(), visitedRefs);
      _refCache[resolvedUrl] = resolved?.DeepClone();

      // Restore previous base URI
      _baseUri = previousBaseUri;

      visitedRefs.Remove(resolvedUrl);
      return resolved;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error loading schema from {ResolvedUrl}", SanitizeUrlForLogging(resolvedUrl));
      visitedRefs.Remove(resolvedUrl);
      return JsonNode.Parse($"{{\"$ref\":\"{refUrl}\"}}");
    }
  }

  private async Task<JsonNode?> ResolveAllRefsAsync(JsonNode? obj, HashSet<string> visitedRefs)
  {
    if (obj == null)
    {
      return null;
    }

    if (obj is JsonValue)
    {
      return obj.DeepClone();
    }

    if (obj is JsonArray jsonArray)
    {
      var resultArray = new JsonArray();
      foreach (var item in jsonArray)
      {
        var resolved = await ResolveAllRefsAsync(item, visitedRefs);
        resultArray.Add(resolved);
      }
      return resultArray;
    }

    if (obj is JsonObject jsonObject)
    {
      // If this object has a $ref, resolve it
      if (jsonObject.TryGetPropertyValue("$ref", out var refNode) &&
          refNode is JsonValue refValue)
      {
        var refString = refValue.GetValue<string>();
        JsonNode? resolved;

        if (IsExternalSchemaRef(refString))
        {
          // Resolve external URL reference
          resolved = await ResolveRefAsync(refString, visitedRefs);
        }
        else if (IsInternalRef(refString))
        {
          // Resolve internal JSON pointer reference
          resolved = await ResolveInternalRefAsync(refString, visitedRefs);
        }
        else
        {
          // Keep the reference as-is if we can't identify it
          return obj.DeepClone();
        }

        // Merge other properties if they exist (besides $ref)
        var otherProps = jsonObject.Where(kvp => kvp.Key != "$ref").ToList();

        if (otherProps.Any() && resolved is JsonObject resolvedObject)
        {
          var merged = new JsonObject();

          // Add resolved properties first
          foreach (var kvp in resolvedObject)
          {
            merged[kvp.Key] = await ResolveAllRefsAsync(kvp.Value, visitedRefs);
          }

          // Add/override with other properties
          foreach (var kvp in otherProps)
          {
            merged[kvp.Key] = await ResolveAllRefsAsync(kvp.Value, visitedRefs);
          }

          return merged;
        }

        return resolved;
      }

      // Otherwise, recursively resolve all properties
      var result = new JsonObject();
      foreach (var kvp in jsonObject)
      {
        result[kvp.Key] = await ResolveAllRefsAsync(kvp.Value, visitedRefs);
      }
      return result;
    }

    return obj;
  }

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution
  /// </summary>
  public async Task<JsonSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default)
  {
    return await CreateSchemaFromJsonAsync(schemaJson, null, null, cancellationToken);
  }

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI.
  /// Handles dynamic anchor conflicts that may arise from duplicate schema definitions.
  /// </summary>
  /// <summary>
  /// Removes competing dynamic anchors from allOf/anyOf/oneOf to prevent JsonSchema.Net registry errors.
  /// When multiple subschemas in a composition keyword have the same dynamic anchor, only keeps it in the first.
  /// </summary>
  private JsonNode? RemoveCompetingDynamicAnchors(JsonNode? schema)
  {
    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();
      var compositionKeywords = new[] { "allOf", "anyOf", "oneOf" };

      foreach (var kvp in jsonObject)
      {
        // Handle composition keywords specially
        if (compositionKeywords.Contains(kvp.Key) && kvp.Value is JsonArray subschemas)
        {
          var seenAnchors = new HashSet<string>();
          var cleanedSubschemas = new JsonArray();

          foreach (var subschema in subschemas)
          {
            if (subschema is JsonObject subObj)
            {
              var cleanedSubObj = new JsonObject();
              
              foreach (var subKvp in subObj)
              {
                // Skip $dynamicAnchor if we've seen it before in this composition
                if (subKvp.Key == "$dynamicAnchor" && subKvp.Value is JsonValue anchorValue)
                {
                  var anchorName = anchorValue.GetValue<string>();
                  if (seenAnchors.Contains(anchorName))
                  {
                    _logger.LogDebug("Removing competing dynamic anchor: {Anchor} from {Keyword}", anchorName, kvp.Key);
                    continue;
                  }
                  seenAnchors.Add(anchorName);
                }

                cleanedSubObj[subKvp.Key] = RemoveCompetingDynamicAnchors(subKvp.Value);
              }
              
              cleanedSubschemas.Add(cleanedSubObj);
            }
            else
            {
              cleanedSubschemas.Add(RemoveCompetingDynamicAnchors(subschema));
            }
          }

          result[kvp.Key] = cleanedSubschemas;
        }
        else
        {
          // Recursively clean other properties
          result[kvp.Key] = RemoveCompetingDynamicAnchors(kvp.Value);
        }
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(RemoveCompetingDynamicAnchors(item));
      }
      return result;
    }

    return schema?.DeepClone();
  }

  /// <summary>
  /// Globally deduplicates dynamic anchors across the entire schema.
  /// Removes all duplicate dynamic anchors, keeping only the first occurrence of each anchor name.
  /// This prevents JsonSchema.Net from throwing "duplicate key" errors when building the schema.
  /// </summary>
  private JsonNode? GloballyDeduplicateDynamicAnchors(JsonNode? schema, HashSet<string>? seenAnchors = null)
  {
    seenAnchors ??= new HashSet<string>();

    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();
      
      foreach (var kvp in jsonObject)
      {
        // Handle dynamic anchors globally - remove if already seen
        if (kvp.Key == "$dynamicAnchor" && kvp.Value is JsonValue anchorValue)
        {
          var anchorName = anchorValue.GetValue<string>();
          if (seenAnchors.Contains(anchorName))
          {
            _logger.LogDebug("Removing duplicate dynamic anchor globally: {Anchor}", anchorName);
            continue; // Skip this anchor, we've seen it before
          }
          seenAnchors.Add(anchorName);
        }

        // Recursively process all properties with the same seen anchors set
        result[kvp.Key] = GloballyDeduplicateDynamicAnchors(kvp.Value, seenAnchors);
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(GloballyDeduplicateDynamicAnchors(item, seenAnchors));
      }
      return result;
    }

    return schema?.DeepClone();
  }

  /// <summary>
  /// Completely strips ALL dynamic anchors AND schema IDs from the schema to prevent registry conflicts.
  /// Used to avoid "duplicate key" and "overwriting registered schemas" errors from JsonSchema.Net.
  /// </summary>
  private JsonNode? StripAllDynamicAnchorsAndIds(JsonNode? schema)
  {
    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();
      
      foreach (var kvp in jsonObject)
      {
        // Skip all $dynamicAnchor and $id properties
        if (kvp.Key == "$dynamicAnchor" || kvp.Key == "$id")
        {
          _logger.LogDebug("Stripping {Property} from schema", kvp.Key);
          continue;
        }

        // Recursively strip from all values
        result[kvp.Key] = StripAllDynamicAnchorsAndIds(kvp.Value);
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(StripAllDynamicAnchorsAndIds(item));
      }
      return result;
    }

    return schema?.DeepClone();
  }

  /// <summary>
  /// Removes non-standard keywords used by OpenReferral schema files
  /// that are not part of the JSON Schema vocabularies.
  /// </summary>
  private JsonNode? StripNonSchemaKeywords(JsonNode? schema)
  {
    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();

      foreach (var kvp in jsonObject)
      {
        if (NonSchemaKeywords.Contains(kvp.Key))
        {
          _logger.LogDebug("Stripping non-schema keyword: {Keyword}", kvp.Key);
          continue;
        }

        result[kvp.Key] = StripNonSchemaKeywords(kvp.Value);
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(StripNonSchemaKeywords(item));
      }
      return result;
    }

    return schema?.DeepClone();
  }

  public async Task<JsonSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, DataSourceAuthentication? auth = null, CancellationToken cancellationToken = default)
  {
    try
    {
      _logger.LogDebug("Creating JSON schema from JSON string with resolver. DocumentUri: {DocumentUri}", documentUri != null ? SanitizeUrlForLogging(documentUri) : "none");

      // Proactively strip dynamic anchors and schema IDs from the input schema upfront.
      // JsonSchema.Net's registry does not permit duplicate anchor names or schema IDs, which can occur
      // when schemas contain the same identifiers in multiple places.
      // These are not essential for validation with JsonSchema.Net, so removing them
      // avoids all registry conflicts.
      var jsonNode = JsonNode.Parse(schemaJson);
      var cleanedNode = StripAllDynamicAnchorsAndIds(jsonNode);
      cleanedNode = StripNonSchemaKeywords(cleanedNode);
      var cleanedJson = cleanedNode?.ToJsonString() ?? schemaJson;

      var buildOptions = new BuildOptions();
      var schema = await Task.Run(() => JsonSchema.FromText(cleanedJson, buildOptions), cancellationToken);
      _logger.LogDebug("Successfully created schema");
      return schema;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to create JSON schema from JSON with resolver. DocumentUri: {DocumentUri}", documentUri ?? "none");
      throw;
    }
  }

  /// <summary>
  /// Completely strips ALL dynamic anchors from the schema.
  /// Used as a last-resort fallback when deduplication still fails.
  /// </summary>
  private JsonNode? StripAllDynamicAnchors(JsonNode? schema)
  {
    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();
      
      foreach (var kvp in jsonObject)
      {
        // Skip all $dynamicAnchor properties
        if (kvp.Key == "$dynamicAnchor")
        {
          _logger.LogDebug("Stripping $dynamicAnchor from schema");
          continue;
        }

        // Recursively strip from all values
        result[kvp.Key] = StripAllDynamicAnchors(kvp.Value);
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(StripAllDynamicAnchors(item));
      }
      return result;
    }

    return schema?.DeepClone();
  }

  /// <summary>
  /// More aggressively removes ALL dynamic anchors from allOf/anyOf/oneOf subschemas.
  /// Used as a fallback when the standard competing anchor removal still fails.
  /// </summary>
  private JsonNode? RemoveAllDynamicAnchorsFromCompositions(JsonNode? schema)
  {
    if (schema is JsonObject jsonObject)
    {
      var result = new JsonObject();
      var compositionKeywords = new[] { "allOf", "anyOf", "oneOf" };

      foreach (var kvp in jsonObject)
      {
        // Handle composition keywords - strip ALL dynamic anchors from subschemas
        if (compositionKeywords.Contains(kvp.Key) && kvp.Value is JsonArray subschemas)
        {
          var cleanedSubschemas = new JsonArray();

          foreach (var subschema in subschemas)
          {
            if (subschema is JsonObject subObj)
            {
              var cleanedSubObj = new JsonObject();
              
              foreach (var subKvp in subObj)
              {
                // Skip all $dynamicAnchor properties in composition subschemas
                if (subKvp.Key == "$dynamicAnchor")
                {
                  _logger.LogDebug("Removing $dynamicAnchor from {Keyword} subschema", kvp.Key);
                  continue;
                }

                cleanedSubObj[subKvp.Key] = RemoveAllDynamicAnchorsFromCompositions(subKvp.Value);
              }
              
              cleanedSubschemas.Add(cleanedSubObj);
            }
            else
            {
              cleanedSubschemas.Add(RemoveAllDynamicAnchorsFromCompositions(subschema));
            }
          }

          result[kvp.Key] = cleanedSubschemas;
        }
        else
        {
          // Recursively clean other properties
          result[kvp.Key] = RemoveAllDynamicAnchorsFromCompositions(kvp.Value);
        }
      }

      return result;
    }
    else if (schema is JsonArray jsonArray)
    {
      var result = new JsonArray();
      foreach (var item in jsonArray)
      {
        result.Add(RemoveAllDynamicAnchorsFromCompositions(item));
      }
      return result;
    }

    return schema?.DeepClone();
  }
}


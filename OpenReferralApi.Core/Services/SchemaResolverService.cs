using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Schema;

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
  /// <returns>The fully resolved schema as a JSON string.</returns>
  Task<string> ResolveAsync(string schema, string? baseUri = null);

  /// <summary>
  /// Resolves all $ref references in the provided schema with a base URI context.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JsonNode).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <returns>The fully resolved schema as a JsonNode.</returns>
  Task<JsonNode?> ResolveAsync(JsonNode schema, string? baseUri = null);

  // Newtonsoft.Json.Schema based schema creation methods
  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution
  /// </summary>
  Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default);

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI
  /// </summary>
  Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string documentUri, CancellationToken cancellationToken = default);
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
  private readonly Dictionary<string, JsonNode?> _refCache = new();
  private readonly HttpClient _httpClient;
  private readonly ILogger<SchemaResolverService> _logger;
  private JsonNode? _rootDocument;
  private string? _baseUri;

  /// <summary>
  /// Initializes a new instance of the SchemaResolver for remote schema resolution.
  /// </summary>
  /// <param name="httpClient">HTTP client for fetching remote schemas.</param>
  /// <param name="logger">Logger instance.</param>
  public SchemaResolverService(HttpClient httpClient, ILogger<SchemaResolverService> logger)
  {
    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    _logger = logger ?? throw new ArgumentNullException(nameof(logger));
  }

  /// <summary>
  /// Resolves all $ref references in the provided schema.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JSON string).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <returns>The fully resolved schema as a JSON string.</returns>
  public async Task<string> ResolveAsync(string schema, string? baseUri = null)
  {
    var jsonNode = JsonNode.Parse(schema);
    if (jsonNode == null)
    {
      throw new ArgumentException("Invalid JSON schema", nameof(schema));
    }

    var resolved = await ResolveAsync(jsonNode, baseUri);
    return resolved?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "null";
  }

  /// <summary>
  /// Resolves all $ref references in the provided schema.
  /// </summary>
  /// <param name="schema">The schema to resolve (as JsonNode).</param>
  /// <param name="baseUri">The base URI for resolving relative references.</param>
  /// <returns>The fully resolved schema as a JsonNode.</returns>
  public async Task<JsonNode?> ResolveAsync(JsonNode schema, string? baseUri = null)
  {
    // Reset state for each resolution
    _refCache.Clear();
    _rootDocument = schema;
    _baseUri = baseUri;

    // Pass a new HashSet to track the current resolution path
    return await ResolveAllRefsAsync(schema, new HashSet<string>());
  }

  private async Task<JsonNode?> LoadRemoteSchemaAsync(string schemaUrl)
  {
    try
    {
      _logger.LogDebug("Fetching remote schema: {SchemaUrl}", schemaUrl);
      var response = await _httpClient.GetAsync(schemaUrl);
      response.EnsureSuccessStatusCode();
      var content = await response.Content.ReadAsStringAsync();
      return JsonNode.Parse(content);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to fetch remote schema: {SchemaUrl}", schemaUrl);
      throw;
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
      _logger.LogWarning("Circular reference detected: {ResolvedUrl}", resolvedUrl);
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
      _logger.LogError(ex, "Error loading schema from {ResolvedUrl}", resolvedUrl);
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
  public async Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default)
  {
    return await CreateSchemaFromJsonAsync(schemaJson, null, cancellationToken);
  }

  /// <summary>
  /// Creates a JSON schema from JSON string with proper reference resolution and base URI
  /// Uses System.Text.Json based resolution to pre-resolve all $ref before creating JSchema
  /// </summary>
  public async Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, CancellationToken cancellationToken = default)
  {
    try
    {
      _logger.LogDebug("Creating JSON schema from JSON string with resolver. DocumentUri: {DocumentUri}", documentUri ?? "none");

      // Pre-resolve all external and internal references using System.Text.Json based resolution
      string resolvedSchemaJson = schemaJson;
      try
      {
        _logger.LogDebug("Pre-resolving all schema references with base URI: {DocumentUri}", documentUri ?? "none");
        resolvedSchemaJson = await ResolveAsync(schemaJson, documentUri);
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
        _logger.LogDebug("Loading schema with base URI: {DocumentUri}", documentUri);
        settings.BaseUri = new Uri(documentUri);
      }

      var schema = await Task.Run(() => JSchema.Parse(resolvedSchemaJson, settings), cancellationToken);

      _logger.LogDebug("Successfully created schema with reference resolution");

      return schema;
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Failed to create JSON schema from JSON with resolver. DocumentUri: {DocumentUri}", documentUri ?? "none");
      throw;
    }
  }
}


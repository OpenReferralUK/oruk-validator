using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Internal helper class for resolving JSON Schema $ref references.
/// Handles both external and internal reference resolution with circular reference detection.
/// </summary>
internal class ReferenceResolver
{
    private readonly ILogger _logger;
    private readonly RemoteSchemaLoader _remoteSchemaLoader;
    private readonly Dictionary<string, JsonNode?> _refCache = new();
    private JsonNode? _rootDocument;
    private string? _baseUri;

    public ReferenceResolver(
        ILogger logger,
        RemoteSchemaLoader remoteSchemaLoader)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _remoteSchemaLoader = remoteSchemaLoader ?? throw new ArgumentNullException(nameof(remoteSchemaLoader));
    }

    /// <summary>
    /// Initializes the resolver for a new resolution session.
    /// </summary>
    public void Initialize(JsonNode? rootDocument, string? baseUri)
    {
        _refCache.Clear();
        _rootDocument = rootDocument;
        _baseUri = baseUri;
    }

    /// <summary>
    /// Resolves all $ref references in the provided JSON node recursively.
    /// </summary>
    public async Task<JsonNode?> ResolveAllRefsAsync(JsonNode? obj, HashSet<string> visitedRefs)
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
                else if (IsLocalSchemaRef(refString))
                {
                    // Resolve local file or relative path reference
                    resolved = await ResolveRefAsync(refString, visitedRefs);
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

            // Flatten resolved allOf properties to make composite fields discoverable.
            MergeAllOfIntoObject(result);

            return result;
        }

        return obj;
    }

    /// <summary>
    /// Resolves an internal JSON pointer reference (e.g., #/definitions/Person).
    /// </summary>
    private async Task<JsonNode?> ResolveInternalRefAsync(string refPointer, HashSet<string> visitedRefs)
    {
        if (_rootDocument == null)
        {
            _logger.LogWarning("Cannot resolve internal reference without root document: {Ref}", refPointer);
            return null;
        }

        if (refPointer == "#")
        {
            return await ResolveAllRefsAsync(_rootDocument, visitedRefs);
        }

        // Check for circular references
        if (visitedRefs.Contains(refPointer))
        {
            _logger.LogDebug("Circular reference detected: {Ref}", refPointer);
            return new JsonObject { ["$ref"] = refPointer };
        }

        visitedRefs.Add(refPointer);

        // Check cache first
        if (_refCache.TryGetValue(refPointer, out var cached))
        {
            return cached?.DeepClone();
        }

        try
        {
            JsonNode? current;

            // JSON Pointer (RFC 6901)
            if (refPointer.StartsWith("#/", StringComparison.Ordinal))
            {
                var pointer = refPointer.TrimStart('#', '/');
                var parts = pointer.Split('/');

                current = _rootDocument;
                foreach (var part in parts)
                {
                    if (string.IsNullOrEmpty(part))
                    {
                        continue;
                    }

                    var unescapedPart = UnescapeJsonPointer(part);

                    if (current is JsonObject jsonObj)
                    {
                        if (!jsonObj.TryGetPropertyValue(unescapedPart, out current) || current == null)
                        {
                            _logger.LogWarning("Failed to resolve internal reference path: {Ref} at part: {Part}", refPointer, unescapedPart);
                            return null;
                        }
                    }
                    else if (current is JsonArray jsonArr)
                    {
                        if (int.TryParse(unescapedPart, out var index) && index >= 0 && index < jsonArr.Count)
                        {
                            current = jsonArr[index];
                        }
                        else
                        {
                            _logger.LogWarning("Invalid array index in reference: {Ref} at part: {Part}", refPointer, unescapedPart);
                            return null;
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Cannot navigate through non-object/non-array in reference: {Ref}", refPointer);
                        return null;
                    }
                }
            }
            else
            {
                // Anchor fragment (e.g. #meta). Supports $anchor and $dynamicAnchor.
                var anchorName = refPointer.TrimStart('#');
                if (string.IsNullOrWhiteSpace(anchorName))
                {
                    return null;
                }

                current = FindAnchorNode(_rootDocument, anchorName);
                if (current == null)
                {
                    _logger.LogWarning("Failed to resolve internal anchor reference: {Ref}", refPointer);
                    return null;
                }
            }

            // Recursively resolve the referenced schema
            var resolved = await ResolveAllRefsAsync(current, visitedRefs);

            // Cache the resolved value
            _refCache[refPointer] = resolved;

            return resolved?.DeepClone();
        }
        finally
        {
            visitedRefs.Remove(refPointer);
        }
    }

    /// <summary>
    /// Resolves an external URL reference (e.g., https://example.com/schema.json#/definitions/Person).
    /// </summary>
    private async Task<JsonNode?> ResolveRefAsync(string refUrl, HashSet<string> visitedRefs)
    {
        // Split URL and fragment
        var parts = refUrl.Split('#');
        var schemaUrl = parts[0];
        var fragment = parts.Length > 1 ? $"#{parts[1]}" : string.Empty;

        var schemaLocation = ResolveSchemaLocation(schemaUrl);
        var resolvedRefKey = string.IsNullOrEmpty(fragment)
            ? schemaLocation
            : $"{schemaLocation}{fragment}";

        // Check for circular references
        if (visitedRefs.Contains(resolvedRefKey))
        {
            _logger.LogDebug("Circular reference detected: {Ref}", SchemaResolverService.SanitizeStringForLogging(resolvedRefKey));
            return new JsonObject { ["$ref"] = refUrl };
        }

        visitedRefs.Add(resolvedRefKey);

        try
        {
            // Check cache first
            if (_refCache.TryGetValue(resolvedRefKey, out var cached))
            {
                return cached?.DeepClone();
            }

            var schema = await LoadSchemaAsync(schemaLocation);

            if (schema == null)
            {
                _logger.LogWarning("Failed to load schema: {Location}", SchemaResolverService.SanitizeStringForLogging(schemaLocation));
                return null;
            }

            JsonNode? resolved;

            // If there's a fragment, resolve it within the loaded schema
            if (!string.IsNullOrEmpty(fragment))
            {
                var previousRoot = _rootDocument;
                var previousBaseUri = _baseUri;

                try
                {
                    _rootDocument = schema;
                    _baseUri = schemaLocation;
                    resolved = await ResolveInternalRefAsync(fragment, visitedRefs);
                }
                finally
                {
                    _rootDocument = previousRoot;
                    _baseUri = previousBaseUri;
                }
            }
            else
            {
                // Recursively resolve references within the loaded schema
                var previousRoot = _rootDocument;
                var previousBaseUri = _baseUri;

                try
                {
                    _rootDocument = schema;
                    _baseUri = schemaLocation;
                    resolved = await ResolveAllRefsAsync(schema, visitedRefs);
                }
                finally
                {
                    _rootDocument = previousRoot;
                    _baseUri = previousBaseUri;
                }
            }

            // Cache the resolved value
            _refCache[resolvedRefKey] = resolved;

            return resolved?.DeepClone();
        }
        finally
        {
            visitedRefs.Remove(resolvedRefKey);
        }
    }

    /// <summary>
    /// Checks if a reference string points to an external schema URL.
    /// </summary>
    private static bool IsExternalSchemaRef(string refString)
    {
        return refString.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
               refString.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Checks if a reference string points to a local schema file path.
    /// </summary>
    private static bool IsLocalSchemaRef(string refString)
    {
        if (string.IsNullOrWhiteSpace(refString))
        {
            return false;
        }

        var schemaPart = refString.Split('#')[0];
        if (string.IsNullOrWhiteSpace(schemaPart))
        {
            return false;
        }

        if (Uri.TryCreate(schemaPart, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.Scheme == Uri.UriSchemeFile;
        }

        return Path.IsPathRooted(schemaPart) ||
               !schemaPart.Contains("://", StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if a reference string is an internal JSON pointer.
    /// </summary>
    private static bool IsInternalRef(string refString)
    {
        return refString.StartsWith("#", StringComparison.Ordinal);
    }

    /// <summary>
    /// Finds a node by JSON Schema anchor name ($anchor or $dynamicAnchor).
    /// </summary>
    private static JsonNode? FindAnchorNode(JsonNode? node, string anchorName)
    {
        if (node == null)
        {
            return null;
        }

        if (node is JsonObject jsonObject)
        {
            if (HasMatchingAnchor(jsonObject, "$anchor", anchorName) ||
                HasMatchingAnchor(jsonObject, "$dynamicAnchor", anchorName))
            {
                return jsonObject;
            }

            foreach (var kvp in jsonObject)
            {
                var found = FindAnchorNode(kvp.Value, anchorName);
                if (found != null)
                {
                    return found;
                }
            }
        }
        else if (node is JsonArray jsonArray)
        {
            foreach (var item in jsonArray)
            {
                var found = FindAnchorNode(item, anchorName);
                if (found != null)
                {
                    return found;
                }
            }
        }

        return null;
    }

    private static bool HasMatchingAnchor(JsonObject node, string propertyName, string anchorName)
    {
        if (!node.TryGetPropertyValue(propertyName, out var anchorNode) ||
            anchorNode is not JsonValue anchorValue)
        {
            return false;
        }

        return string.Equals(anchorValue.GetValue<string>(), anchorName, StringComparison.Ordinal);
    }

    /// <summary>
    /// Resolves a schema location against the current base URI/path.
    /// </summary>
    private string ResolveSchemaLocation(string schemaRef)
    {
        if (string.IsNullOrWhiteSpace(schemaRef))
        {
            return _baseUri ?? string.Empty;
        }

        if (Uri.TryCreate(schemaRef, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.Scheme == Uri.UriSchemeFile
                ? absoluteUri.LocalPath
                : schemaRef;
        }

        if (string.IsNullOrWhiteSpace(_baseUri))
        {
            return Path.GetFullPath(schemaRef);
        }

        if (Uri.TryCreate(_baseUri, UriKind.Absolute, out var baseUri))
        {
            if (Uri.TryCreate(baseUri, schemaRef, out var resolvedUri))
            {
                return resolvedUri.Scheme == Uri.UriSchemeFile
                    ? resolvedUri.LocalPath
                    : resolvedUri.ToString();
            }
        }

        var basePath = _baseUri;
        if (!string.IsNullOrEmpty(Path.GetExtension(basePath)))
        {
            basePath = Path.GetDirectoryName(basePath) ?? basePath;
        }

        return Path.GetFullPath(Path.Combine(basePath, schemaRef));
    }

    /// <summary>
    /// Loads a schema from HTTP(S) or a local file path.
    /// </summary>
    private async Task<JsonNode?> LoadSchemaAsync(string schemaLocation)
    {
        if (Uri.TryCreate(schemaLocation, UriKind.Absolute, out var schemaUri) &&
            (schemaUri.Scheme == Uri.UriSchemeHttp || schemaUri.Scheme == Uri.UriSchemeHttps))
        {
            return await _remoteSchemaLoader.LoadRemoteSchemaAsync(schemaLocation);
        }

        var localPath = schemaLocation;
        if (Uri.TryCreate(schemaLocation, UriKind.Absolute, out var fileUri) &&
            fileUri.Scheme == Uri.UriSchemeFile)
        {
            localPath = fileUri.LocalPath;
        }

        if (!File.Exists(localPath))
        {
            _logger.LogWarning("Schema file not found: {Path}", SchemaResolverService.SanitizeStringForLogging(localPath));
            return null;
        }

        try
        {
            var content = await File.ReadAllTextAsync(localPath);
            return JsonNode.Parse(content);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load local schema file: {Path}", SchemaResolverService.SanitizeStringForLogging(localPath));
            throw;
        }
    }

    /// <summary>
    /// Unescapes a JSON pointer token according to RFC 6901.
    /// </summary>
    private static string UnescapeJsonPointer(string token)
    {
        return token.Replace("~1", "/").Replace("~0", "~");
    }

    /// <summary>
    /// Merges allOf properties into the target object to make composite fields discoverable.
    /// </summary>
    private static void MergeAllOfIntoObject(JsonObject target)
    {
        if (!target.TryGetPropertyValue("allOf", out var allOfNode) || allOfNode is not JsonArray allOfArray)
        {
            return;
        }

        JsonObject? targetProperties = null;
        if (target.TryGetPropertyValue("properties", out var propsNode) && propsNode is JsonObject propsObject)
        {
            targetProperties = propsObject;
        }

        JsonArray? targetRequired = null;
        if (target.TryGetPropertyValue("required", out var requiredNode) && requiredNode is JsonArray requiredArray)
        {
            targetRequired = requiredArray;
        }

        foreach (var item in allOfArray)
        {
            if (item is not JsonObject itemObject)
            {
                continue;
            }

            if (itemObject.TryGetPropertyValue("properties", out var itemPropsNode) && itemPropsNode is JsonObject itemProps)
            {
                targetProperties ??= new JsonObject();

                foreach (var kvp in itemProps)
                {
                    if (!targetProperties.ContainsKey(kvp.Key))
                    {
                        targetProperties[kvp.Key] = kvp.Value?.DeepClone();
                    }
                }
            }

            if (itemObject.TryGetPropertyValue("required", out var itemRequiredNode) && itemRequiredNode is JsonArray itemRequired)
            {
                targetRequired ??= new JsonArray();

                foreach (var requiredItem in itemRequired)
                {
                    if (requiredItem is not JsonValue requiredValue)
                    {
                        continue;
                    }

                    var requiredName = requiredValue.GetValue<string>();
                    if (!targetRequired.Any(existing => existing?.GetValue<string>() == requiredName))
                    {
                        targetRequired.Add(requiredName);
                    }
                }
            }

            if (!target.TryGetPropertyValue("type", out _) &&
                itemObject.TryGetPropertyValue("type", out var itemTypeNode))
            {
                target["type"] = itemTypeNode?.DeepClone();
            }
        }

        if (targetProperties != null)
        {
            target["properties"] = targetProperties;
        }

        if (targetRequired != null)
        {
            target["required"] = targetRequired;
        }
    }
}

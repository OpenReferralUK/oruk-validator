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
            var pointer = refPointer.TrimStart('#', '/');
            var parts = pointer.Split('/');

            JsonNode? current = _rootDocument;
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

        // Check for circular references
        if (visitedRefs.Contains(refUrl))
        {
            _logger.LogDebug("Circular reference detected: {Ref}", SchemaResolverService.SanitizeUrlForLogging(refUrl));
            return new JsonObject { ["$ref"] = refUrl };
        }

        visitedRefs.Add(refUrl);

        try
        {
            // Check cache first
            if (_refCache.TryGetValue(refUrl, out var cached))
            {
                return cached?.DeepClone();
            }

            // Resolve relative URLs using base URI
            var absoluteUrl = schemaUrl;
            if (!string.IsNullOrEmpty(_baseUri) && !string.IsNullOrEmpty(schemaUrl))
            {
                if (!Uri.TryCreate(schemaUrl, UriKind.Absolute, out _))
                {
                    if (Uri.TryCreate(new Uri(_baseUri), schemaUrl, out var resolvedUri))
                    {
                        absoluteUrl = resolvedUri.ToString();
                        _logger.LogDebug("Resolved relative URL {RelativeUrl} to {AbsoluteUrl}",
                            SchemaResolverService.SanitizeUrlForLogging(schemaUrl),
                            SchemaResolverService.SanitizeUrlForLogging(absoluteUrl));
                    }
                }
            }

            // Load remote schema
            var schema = await _remoteSchemaLoader.LoadRemoteSchemaAsync(absoluteUrl);

            if (schema == null)
            {
                _logger.LogWarning("Failed to load remote schema: {Url}", SchemaResolverService.SanitizeUrlForLogging(absoluteUrl));
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
                    _baseUri = absoluteUrl;
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
                    _baseUri = absoluteUrl;
                    resolved = await ResolveAllRefsAsync(schema, visitedRefs);
                }
                finally
                {
                    _rootDocument = previousRoot;
                    _baseUri = previousBaseUri;
                }
            }

            // Cache the resolved value
            _refCache[refUrl] = resolved;

            return resolved?.DeepClone();
        }
        finally
        {
            visitedRefs.Remove(refUrl);
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
    /// Checks if a reference string is an internal JSON pointer.
    /// </summary>
    private static bool IsInternalRef(string refString)
    {
        return refString.StartsWith("#/", StringComparison.Ordinal);
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

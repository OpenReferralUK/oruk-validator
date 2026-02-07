using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Service for resolving JSON Schema references and creating schemas with proper resolution using Newtonsoft.Json.Schema
/// </summary>
public interface IJsonSchemaResolverService
{
    Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, CancellationToken cancellationToken = default);
    Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string documentUri, CancellationToken cancellationToken = default);
    Task<JSchema> CreateSchemaFromUriAsync(string schemaUri, CancellationToken cancellationToken = default);
    Task<JSchema> ResolveSchemaAsync(JSchema schema, CancellationToken cancellationToken = default);
    Task<JSchema> CreateSchemaWithOpenApiContextAsync(string schemaJson, JObject openApiDocument, string? documentUri, CancellationToken cancellationToken = default);
}

/// <summary>
/// Implementation of JSON Schema resolver service that handles $ref resolution
/// Uses SchemaResolverService to pre-resolve all remote $ref references,
/// then creates JSchema with fully resolved schema
/// </summary>
public class JsonSchemaResolverService : IJsonSchemaResolverService
{
    private readonly ILogger<JsonSchemaResolverService> _logger;
    private readonly HttpClient _httpClient;
    private readonly ISchemaResolverService? _schemaResolverService;

    public JsonSchemaResolverService(
        ILogger<JsonSchemaResolverService> logger,
        HttpClient httpClient,
        ISchemaResolverService? schemaResolverService = null)
    {
        _logger = logger;
        _httpClient = httpClient;
        _schemaResolverService = schemaResolverService;
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
    /// Uses SchemaResolverService to pre-resolve all $ref before creating JSchema
    /// </summary>
    public async Task<JSchema> CreateSchemaFromJsonAsync(string schemaJson, string? documentUri, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Creating JSON schema from JSON string with resolver. DocumentUri: {DocumentUri}", documentUri ?? "none");

            // Pre-resolve all external and internal references using SchemaResolverService
            string resolvedSchemaJson = schemaJson;
            if (_schemaResolverService != null)
            {
                try
                {
                    _logger.LogDebug("Pre-resolving all schema references using SchemaResolverService with base URI: {DocumentUri}", documentUri ?? "none");
                    resolvedSchemaJson = await _schemaResolverService.ResolveAsync(schemaJson, documentUri);
                    _logger.LogDebug("Successfully pre-resolved all schema references");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to pre-resolve schema with SchemaResolverService, continuing with original schema");
                    // Continue with original schema if resolution fails
                    resolvedSchemaJson = schemaJson;
                }
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

    /// <summary>
    /// Creates a JSON schema from URI with proper reference resolution
    /// Uses JSchemaUrlResolver for proper external reference handling
    /// </summary>
    public async Task<JSchema> CreateSchemaFromUriAsync(string schemaUri, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Creating JSON schema from URI with document context: {SchemaUri}", schemaUri);

            // Create resolver for external references
            var resolver = new JSchemaUrlResolver();

            // First fetch the schema content manually since JSchema.Load doesn't support async loading from URI
            var response = await _httpClient.GetStringAsync(schemaUri, cancellationToken);

            // Load schema from JSON string with resolver settings
            var settings = new JSchemaReaderSettings
            {
                Resolver = resolver,
                BaseUri = new Uri(schemaUri)
            };

            using var reader = new JsonTextReader(new StringReader(response));
            var schema = await Task.Run(() => JSchema.Load(reader, settings), cancellationToken);
            _logger.LogDebug("Successfully loaded schema from URI with JSchemaUrlResolver");

            return schema;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create JSON schema from URI: {SchemaUri}", schemaUri);
            throw;
        }
    }

    /// <summary>
    /// Resolves all references in a JSchema - JSchema handles this automatically during loading,
    /// so this method primarily validates that the schema is properly resolved
    /// </summary>
    public async Task<JSchema> ResolveSchemaAsync(JSchema schema, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Validating schema reference resolution");

            // JSchema resolves references during loading, so we just return the schema
            // The schema should already have all references resolved by the JSchemaUrlResolver
            await Task.CompletedTask; // Keep async signature for consistency
            return schema;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during schema resolution validation");
            return schema; // Return original schema if validation fails
        }
    }

    /// <summary>
    /// Creates a JSON schema from JSON string with OpenAPI document context for resolving internal references
    /// This method resolves internal OpenAPI references like #/components/schemas/Page by providing the full OpenAPI document context
    /// </summary>
    public async Task<JSchema> CreateSchemaWithOpenApiContextAsync(string schemaJson, JObject openApiDocument, string? documentUri, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Creating JSON schema with OpenAPI context. DocumentUri: {DocumentUri}", documentUri ?? "none");

            // First, try to resolve the schema by expanding all internal references manually
            var expandedSchemaJson = await ExpandOpenApiReferences(schemaJson, openApiDocument, cancellationToken);

            // Parse the expanded schema using standard resolver
            using var reader = new JsonTextReader(new StringReader(expandedSchemaJson));

            var settings = new JSchemaReaderSettings
            {
                Resolver = new JSchemaUrlResolver()
            };

            // Set base URI for relative reference resolution if provided
            if (!string.IsNullOrEmpty(documentUri))
            {
                _logger.LogDebug("Loading schema with base URI for reference resolution: {DocumentUri}", documentUri);
                settings.BaseUri = new Uri(documentUri);
            }

            var schema = await Task.Run(() => JSchema.Load(reader, settings), cancellationToken);
            _logger.LogDebug("Successfully created schema with OpenAPI context resolver");

            return schema;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create JSON schema with OpenAPI context. DocumentUri: {DocumentUri}", documentUri ?? "none");
            throw;
        }
    }

    /// <summary>
    /// Manually expand all OpenAPI internal references in a schema JSON by replacing them with actual schema content
    /// </summary>
    private async Task<string> ExpandOpenApiReferences(string schemaJson, JObject openApiDocument, CancellationToken cancellationToken)
    {
        await Task.CompletedTask; // Keep async for future enhancements

        var schemaToken = JToken.Parse(schemaJson);
        var expandedSchema = ExpandReferencesRecursively(schemaToken, openApiDocument, new HashSet<string>());
        return expandedSchema.ToString();
    }

    /// <summary>
    /// Recursively expand all $ref references in a JToken by replacing them with actual content
    /// </summary>
    private JToken ExpandReferencesRecursively(JToken token, JObject openApiDocument, HashSet<string> visitedRefs)
    {
        switch (token.Type)
        {
            case JTokenType.Object:
                var obj = (JObject)token;

                // Check if this is a $ref object
                if (obj.ContainsKey("$ref"))
                {
                    var refValue = obj["$ref"]?.ToString();
                    if (!string.IsNullOrEmpty(refValue) && refValue.StartsWith("#/"))
                    {
                        // Prevent circular references
                        if (visitedRefs.Contains(refValue))
                        {
                            return new JObject { ["type"] = "object" }; // Return empty object schema to break cycles
                        }

                        visitedRefs.Add(refValue);

                        var schemaPath = refValue.TrimStart('#').TrimStart('/');
                        var referencedSchema = GetSchemaFromPath(openApiDocument, schemaPath);

                        if (referencedSchema != null)
                        {
                            // Recursively expand references in the resolved schema
                            var expandedRef = ExpandReferencesRecursively(referencedSchema, openApiDocument, visitedRefs);
                            visitedRefs.Remove(refValue);
                            return expandedRef;
                        }

                        visitedRefs.Remove(refValue);
                    }

                    return obj; // Return as-is if we can't resolve
                }

                // Recursively process all properties
                var newObj = new JObject();
                foreach (var property in obj.Properties())
                {
                    newObj[property.Name] = ExpandReferencesRecursively(property.Value, openApiDocument, visitedRefs);
                }
                return newObj;

            case JTokenType.Array:
                var array = (JArray)token;
                var newArray = new JArray();
                foreach (var item in array)
                {
                    newArray.Add(ExpandReferencesRecursively(item, openApiDocument, visitedRefs));
                }
                return newArray;

            default:
                return token.DeepClone(); // Return primitive values as-is
        }
    }

    /// <summary>
    /// Helper method to extract a schema from a given path in the OpenAPI document
    /// </summary>
    private static JToken? GetSchemaFromPath(JObject document, string path)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        JToken? current = document;

        foreach (var part in parts)
        {
            if (current is JObject obj && obj.ContainsKey(part))
            {
                current = obj[part];
            }
            else if (current is JArray array && int.TryParse(part, out var index) && index >= 0 && index < array.Count)
            {
                current = array[index];
            }
            else
            {
                return null; // Path not found
            }
        }

        return current;
    }
}

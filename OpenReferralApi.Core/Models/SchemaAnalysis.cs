using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Provides detailed analysis of the OpenAPI specification's schema structure and component organization
/// </summary>
public class SchemaAnalysis
{
    /// <summary>
    /// Number of component sections found in the specification (typically 1 for OpenAPI 3.x)
    /// Indicates whether the spec uses the modern components structure for reusable elements
    /// </summary>
    [JsonProperty("componentCount")]
    public int ComponentCount { get; set; }

    /// <summary>
    /// Total number of reusable schema definitions (data models)
    /// Represents the complexity of the API's data structures and reusability
    /// </summary>
    [JsonProperty("schemaCount")]
    public int SchemaCount { get; set; }

    /// <summary>
    /// Number of reusable response definitions in the components section
    /// Indicates how well response structures are organized and reused across endpoints
    /// </summary>
    [JsonProperty("responseCount")]
    public int ResponseCount { get; set; }

    /// <summary>
    /// Number of reusable parameter definitions in the components section
    /// Shows the level of parameter standardization and reuse across the API
    /// </summary>
    [JsonProperty("parameterCount")]
    public int ParameterCount { get; set; }

    /// <summary>
    /// Number of reusable request body definitions in the components section
    /// Indicates standardization of input data structures across operations
    /// </summary>
    [JsonProperty("requestBodyCount")]
    public int RequestBodyCount { get; set; }

    /// <summary>
    /// Number of reusable header definitions in the components section
    /// Shows standardization of HTTP headers used across the API
    /// </summary>
    [JsonProperty("headerCount")]
    public int HeaderCount { get; set; }

    /// <summary>
    /// Total number of example definitions found throughout the specification
    /// Higher counts indicate better documentation and testing support
    /// </summary>
    [JsonProperty("exampleCount")]
    public int ExampleCount { get; set; }

    /// <summary>
    /// Number of link definitions for connecting related operations
    /// Indicates the level of HATEOAS (Hypermedia as the Engine of Application State) implementation
    /// </summary>
    [JsonProperty("linkCount")]
    public int LinkCount { get; set; }

    /// <summary>
    /// Number of callback definitions for asynchronous operations
    /// Shows whether the API includes webhook or event-driven capabilities
    /// </summary>
    [JsonProperty("callbackCount")]
    public int CallbackCount { get; set; }

    /// <summary>
    /// Total number of $ref references that have been resolved in the specification
    /// Higher numbers indicate greater use of reusable components and modular design
    /// </summary>
    [JsonProperty("referencesResolved")]
    public int ReferencesResolved { get; set; }

    /// <summary>
    /// List of circular reference paths detected in the schema definitions
    /// Circular references can cause issues in code generation and documentation tools
    /// </summary>
    [JsonProperty("circularReferences")]
    public List<string> CircularReferences { get; set; } = new();
}

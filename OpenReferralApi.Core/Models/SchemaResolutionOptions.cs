namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration for schema resolution behavior.
/// </summary>
public class SchemaResolutionOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "SchemaResolution";

    /// <summary>
    /// Known canonical JSON Schema meta-schema URLs used for normalization and cache key stability.
    /// </summary>
    public List<string> KnownJsonSchemaUrls { get; set; } =
    [
        "https://json-schema.org/draft/2020-12/schema",
        "https://json-schema.org/draft/2020-12/meta/core",
        "https://json-schema.org/draft/2020-12/meta/applicator",
        "https://json-schema.org/draft/2020-12/meta/unevaluated",
        "https://json-schema.org/draft/2020-12/meta/validation",
        "https://json-schema.org/draft/2020-12/meta/meta-data",
        "https://json-schema.org/draft/2020-12/meta/format-annotation",
        "https://json-schema.org/draft/2020-12/meta/content"
    ];

    /// <summary>
    /// Whether to emit warning logs when a json-schema.org draft URL is encountered but not present in KnownJsonSchemaUrls.
    /// </summary>
    public bool WarnOnUnknownJsonSchemaDraft { get; set; } = true;
}

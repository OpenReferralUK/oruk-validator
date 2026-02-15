using System.Text.Json;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Provides shared, reusable JsonSerializerOptions instances to avoid creating
/// duplicate configurations across the application.
/// </summary>
public interface IJsonSerializationOptionsProvider
{
    /// <summary>
    /// Gets JsonSerializerOptions configured for pretty-printing (human-readable formatting).
    /// Used for logging, validation error reporting, and debugging output.
    /// </summary>
    JsonSerializerOptions PrettyPrintOptions { get; }
}

/// <summary>
/// Provides shared, reusable JsonSerializerOptions instances.
/// This centralizes serialization configuration, making it easy to maintain
/// and update JSON formatting settings across the application.
/// </summary>
public class JsonSerializationOptionsProvider : IJsonSerializationOptionsProvider
{
    private static readonly JsonSerializerOptions _prettyPrintOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Gets JsonSerializerOptions configured for pretty-printing (human-readable formatting).
    /// Used for logging, validation error reporting, and debugging output.
    /// </summary>
    public JsonSerializerOptions PrettyPrintOptions => _prettyPrintOptions;
}

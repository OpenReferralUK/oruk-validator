namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for OpenTelemetry observability
/// </summary>
public class OpenTelemetryOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "OpenTelemetry";

    /// <summary>
    /// Whether OpenTelemetry is enabled
    /// Default: false
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// OTLP exporter endpoint URL
    /// Example: http://localhost:4317
    /// </summary>
    public string? OtlpEndpoint { get; set; }
}

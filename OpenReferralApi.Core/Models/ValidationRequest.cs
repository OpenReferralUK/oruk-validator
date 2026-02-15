using System;
using System.ComponentModel;
using System.Text.Json.Serialization;

namespace OpenReferralApi.Core.Models;

public class ValidationRequest
{
    [JsonPropertyName("jsonData")]
    public object? JsonData { get; set; }

    [JsonPropertyName("dataUrl")]
    public string? DataUrl { get; set; }

    [JsonPropertyName("schema")]
    public object? Schema { get; set; }

    [JsonPropertyName("schemaUri")]
    public string? SchemaUri { get; set; }

    [JsonPropertyName("options")]
    public ValidationOptions? Options { get; set; }
}

public class ValidationOptions
{
    [JsonPropertyName("strictMode")]
    public bool StrictMode { get; set; } = false;

    [JsonPropertyName("allowAdditionalProperties")]
    public bool AllowAdditionalProperties { get; set; } = true;

    [JsonPropertyName("validateFormat")]
    public bool ValidateFormat { get; set; } = true;

    [JsonPropertyName("maxErrors")]
    public int MaxErrors { get; set; } = 100;

    [DefaultValue(30)]
    [JsonPropertyName("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 30;

    [DefaultValue(5)]
    [JsonPropertyName("maxConcurrentRequests")]
    public int MaxConcurrentRequests { get; set; } = 5;

    [JsonPropertyName("useThrottling")]
    public bool UseThrottling { get; set; } = true;

    [JsonPropertyName("retryAttempts")]
    public int RetryAttempts { get; set; } = 3;

    [JsonPropertyName("retryDelaySeconds")]
    public int RetryDelaySeconds { get; set; } = 1;

    [JsonPropertyName("enableCaching")]
    public bool EnableCaching { get; set; } = true;

    [JsonPropertyName("cacheTtlMinutes")]
    public int CacheTtlMinutes { get; set; } = 30;

    [JsonPropertyName("followRedirects")]
    public bool FollowRedirects { get; set; } = true;

    [JsonPropertyName("maxRedirects")]
    public int MaxRedirects { get; set; } = 5;

    [JsonPropertyName("validateSslCertificate")]
    public bool ValidateSslCertificate { get; set; } = true;
}


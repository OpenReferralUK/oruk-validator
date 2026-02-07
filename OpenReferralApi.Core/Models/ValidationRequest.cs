using System;
using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

public class ValidationRequest
{
    [JsonProperty("jsonData")]
    public object? JsonData { get; set; }

    [JsonProperty("dataUrl")]
    public string? DataUrl { get; set; }

    [JsonProperty("schema")]
    public object? Schema { get; set; }

    [JsonProperty("schemaUri")]
    public string? SchemaUri { get; set; }

    [JsonProperty("options")]
    public ValidationOptions? Options { get; set; }
}

public class ValidationOptions
{
    [JsonProperty("strictMode")]
    public bool StrictMode { get; set; } = false;

    [JsonProperty("allowAdditionalProperties")]
    public bool AllowAdditionalProperties { get; set; } = true;

    [JsonProperty("validateFormat")]
    public bool ValidateFormat { get; set; } = true;

    [JsonProperty("maxErrors")]
    public int MaxErrors { get; set; } = 100;

    [DefaultValue(30)]
    [JsonProperty("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 30;

    [DefaultValue(5)]
    [JsonProperty("maxConcurrentRequests")]
    public int MaxConcurrentRequests { get; set; } = 5;

    [JsonProperty("useThrottling")]
    public bool UseThrottling { get; set; } = true;

    [JsonProperty("retryAttempts")]
    public int RetryAttempts { get; set; } = 3;

    [JsonProperty("retryDelaySeconds")]
    public int RetryDelaySeconds { get; set; } = 1;

    [JsonProperty("enableCaching")]
    public bool EnableCaching { get; set; } = true;

    [JsonProperty("cacheTtlMinutes")]
    public int CacheTtlMinutes { get; set; } = 30;

    [JsonProperty("followRedirects")]
    public bool FollowRedirects { get; set; } = true;

    [JsonProperty("maxRedirects")]
    public int MaxRedirects { get; set; } = 5;

    [JsonProperty("validateSslCertificate")]
    public bool ValidateSslCertificate { get; set; } = true;
}


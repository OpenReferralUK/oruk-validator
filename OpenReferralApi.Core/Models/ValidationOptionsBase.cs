using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

public abstract class ValidationOptionsBase
{
    [DefaultValue(30)]
    [JsonProperty("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 30;

    [DefaultValue(5)]
    [JsonProperty("maxConcurrentRequests")]
    public int MaxConcurrentRequests { get; set; } = 5;

    [JsonProperty("reportAdditionalFields")]
    public bool ReportAdditionalFields { get; set; } = false;
}
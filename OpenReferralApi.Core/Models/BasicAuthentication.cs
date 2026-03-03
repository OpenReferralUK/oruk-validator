using System.ComponentModel;
using Newtonsoft.Json;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents basic authentication credentials for HTTP requests
/// </summary>
public class BasicAuthentication
{
    [DefaultValue("")]
    [JsonProperty("username")]
    public string Username { get; set; } = string.Empty;

    [DefaultValue("")]
    [JsonProperty("password")]
    public string Password { get; set; } = string.Empty;
}

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Common authentication contract used by services that apply auth headers to outgoing HTTP requests.
/// </summary>
public interface IAuthenticationConfig
{
    string? ApiKey { get; set; }
    string ApiKeyHeader { get; set; }
    string? BearerToken { get; set; }
    BasicAuthentication? BasicAuth { get; set; }
    Dictionary<string, string>? CustomHeaders { get; set; }
}
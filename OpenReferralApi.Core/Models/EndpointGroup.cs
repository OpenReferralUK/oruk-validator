namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents an endpoint group with collection and parameterized endpoints
/// </summary>
public class EndpointGroup
{
    public string RootPath { get; set; } = string.Empty;
    public List<EndpointInfo> CollectionEndpoints { get; set; } = new();
    public List<EndpointInfo> ParameterizedEndpoints { get; set; } = new();
    public List<EndpointInfo> Endpoints => CollectionEndpoints.Concat(ParameterizedEndpoints).ToList();
}

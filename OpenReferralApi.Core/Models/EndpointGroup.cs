using System;
using System.Text.Json.Nodes;

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

/// <summary>
/// Represents a single endpoint with its metadata
/// </summary>
public class EndpointInfo
{
    public string Path { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public JsonObject Operation { get; set; } = new();
    public JsonObject PathItem { get; set; } = new();
    public bool IsParameterized => Path.Contains('{');
    public string RootPath => GetRootPath(Path);

    /// <summary>
    /// Gets the root path from a full path (e.g., /services/{id} -> /services)
    /// </summary>
    private static string GetRootPath(string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
            return "/";

        // Take segments until we hit a parameter
        var rootSegments = new List<string>();
        foreach (var segment in segments)
        {
            if (segment.StartsWith('{') && segment.EndsWith('}'))
                break;
            rootSegments.Add(segment);
        }

        return rootSegments.Any() ? "/" + string.Join("/", rootSegments) : "/";
    }
}

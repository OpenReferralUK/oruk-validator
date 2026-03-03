namespace OpenReferralApi.Core.Models;

/// <summary>
/// Status of an optional endpoint validation
/// </summary>
public enum OptionalEndpointStatus
{
    Required,        // Endpoint is required and must be implemented
    Implemented,     // Optional endpoint is implemented
    NotImplemented,  // Optional endpoint is not implemented (acceptable)
    Error            // Optional endpoint returned an error
}

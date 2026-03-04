using Microsoft.AspNetCore.Mvc;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Controllers;

/// <summary>
/// Base controller for OpenAPI validation endpoints
/// Provides shared validation logic for different response format implementations
/// </summary>
public abstract class BaseOpenApiController : ControllerBase
{
    /// <summary>
    /// Validates the incoming request for required fields
    /// </summary>
    /// <param name="request">The validation request to validate</param>
    /// <returns>A BadRequest ActionResult if validation fails, null if validation passes</returns>
    protected ActionResult? ValidateRequestAndReturnErrorIfInvalid(
        OpenApiValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.OpenApiSchema?.Url) && string.IsNullOrEmpty(request.BaseUrl))
        {
            return BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                ["request"] = new[] { "OpenAPI schema URL must be provided or discoverable from baseUrl" }
            }));
        }

        if (string.IsNullOrEmpty(request.BaseUrl))
        {
            return BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                ["baseUrl"] = new[] { "BaseUrl is required when testing endpoints" }
            }));
        }

        return null;
    }
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
[EnableRateLimiting("fixed")]
public class OpenApiController : ControllerBase
{
    private readonly IOpenApiValidationService _openApiValidationService;
    private readonly ILogger<OpenApiController> _logger;
    private readonly IOpenApiToValidationResponseMapper _mapper;

    public OpenApiController(
        IOpenApiValidationService openApiValidationService,
        ILogger<OpenApiController> logger,
        IOpenApiToValidationResponseMapper mapper)
    {
        _openApiValidationService = openApiValidationService;
        _logger = logger;
        _mapper = mapper;
    }

    /// <summary>
    /// Validates an OpenAPI specification and optionally tests all defined endpoints
    /// </summary>
    /// <param name="request">The validation request containing OpenAPI URL and base URL</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Validation results with endpoint test outcomes</returns>
    /// <response code="200">Validation completed successfully</response>
    /// <response code="400">Invalid request parameters</response>
    /// <response code="429">Rate limit exceeded</response>
    /// <response code="500">Internal server error</response>
    [HttpPost("validate")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<object>> ValidateOpenApiSpecificationAsync(
        [FromBody] OpenApiValidationRequest request,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Received OpenAPI validation request for BaseUrl: {BaseUrl}", SchemaResolverService.SanitizeUrlForLogging(request.BaseUrl ?? string.Empty));

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

        var result = await _openApiValidationService.ValidateOpenApiSpecificationAsync(request, cancellationToken);
        
        _logger.LogInformation("Validation completed for BaseUrl: {BaseUrl}", SchemaResolverService.SanitizeUrlForLogging(request.BaseUrl ?? string.Empty));

        // Return raw result or mapped to ValidationResponse format based on option
        if (request.Options?.ReturnRawResult == true)
        {
            return Ok(result);
        }
        else
        {
            var mappedResult = _mapper.MapToValidationResponse(result);
            return Ok(mappedResult);
        }
    }
}

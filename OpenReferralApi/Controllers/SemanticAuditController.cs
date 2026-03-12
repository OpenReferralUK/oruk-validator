using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Controllers;

[ApiController]
[Route("api/semantic-audit")]
[Produces("application/json")]
[EnableRateLimiting("fixed")]
[ApiExplorerSettings(GroupName = "v1")]
public class SemanticAuditController : ControllerBase
{
    private readonly ISemanticDataAuditService _semanticDataAuditService;
    private readonly ILogger<SemanticAuditController> _logger;

    public SemanticAuditController(
        ISemanticDataAuditService semanticDataAuditService,
        ILogger<SemanticAuditController> logger)
    {
        _semanticDataAuditService = semanticDataAuditService;
        _logger = logger;
    }

    /// <summary>
    /// Performs semantic consistency checks between service descriptions and assigned taxonomy terms.
    /// Request can include service records directly, or a source base URL for automatic data fetch.
    /// </summary>
    [HttpPost("validate")]
    [ProducesResponseType(typeof(SemanticDataAuditResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<SemanticDataAuditResponse>> ValidateAsync(
        [FromBody] SemanticDataAuditRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        _logger.LogInformation(
            "Received semantic data audit request. InlineServices={ServiceCount}, SourceBaseUrlConfigured={HasSource}",
            request.Services.Count,
            !string.IsNullOrWhiteSpace(request.SourceBaseUrl));

        var response = await _semanticDataAuditService.AuditAsync(request, cancellationToken);

        _logger.LogInformation(
            "Semantic data audit completed. Total={TotalServices}, Flagged={FlaggedServices}",
            response.TotalServices,
            response.FlaggedServices);

        return Ok(response);
    }
}

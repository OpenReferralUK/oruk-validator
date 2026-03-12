using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Controllers;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Controllers;

[TestFixture]
public class SemanticAuditControllerTests
{
    private Mock<ISemanticDataAuditService> _semanticAuditServiceMock;
    private Mock<ILogger<SemanticAuditController>> _loggerMock;
    private SemanticAuditController _controller;

    [SetUp]
    public void Setup()
    {
        _semanticAuditServiceMock = new Mock<ISemanticDataAuditService>();
        _loggerMock = new Mock<ILogger<SemanticAuditController>>();

        _controller = new SemanticAuditController(
            _semanticAuditServiceMock.Object,
            _loggerMock.Object);
    }

    [Test]
    public async Task ValidateAsync_WithValidRequest_ReturnsOkResult()
    {
        var request = new SemanticDataAuditRequest
        {
            Services = new List<SemanticAuditServiceRecord>
            {
                new()
                {
                    ServiceId = "svc-1",
                    ServiceDescription = "Emergency food parcel support",
                    TaxonomyTerm = "Food Bank"
                }
            }
        };

        var expected = new SemanticDataAuditResponse
        {
            TotalServices = 1,
            FlaggedServices = 0
        };

        _semanticAuditServiceMock
            .Setup(x => x.AuditAsync(It.IsAny<SemanticDataAuditRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expected);

        var result = await _controller.ValidateAsync(request);

        Assert.That(result.Result, Is.TypeOf<OkObjectResult>());
        var ok = (OkObjectResult)result.Result!;
        Assert.That(ok.Value, Is.TypeOf<SemanticDataAuditResponse>());
        _semanticAuditServiceMock.Verify(x => x.AuditAsync(request, It.IsAny<CancellationToken>()), Times.Once);
    }
}

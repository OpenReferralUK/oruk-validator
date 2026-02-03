using Newtonsoft.Json.Linq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OpenApiToValidationResponseMapperTests
{
    private OpenApiToValidationResponseMapper _mapper;

    [SetUp]
    public void Setup()
    {
        _mapper = new OpenApiToValidationResponseMapper();
    }

    [Test]
    public void MapToValidationResponse_WithValidResult_ReturnsCorrectStructure()
    {
        // Arrange
        var result = new OpenApiValidationResult
        {
            IsValid = true,
            Metadata = new OpenApiValidationMetadata
            {
                BaseUrl = "https://api.example.com"
            },
            SpecificationValidation = new OpenApiSpecificationValidation
            {
                IsValid = true,
                Version = "3.0",
                Errors = new List<ValidationError>()
            },
            Summary = new OpenApiValidationSummary
            {
                TotalEndpoints = 5,
                SuccessfulTests = 5,
                FailedTests = 0
            },
            EndpointTests = new List<EndpointTestResult>()
        };

        // Act
        var response = _mapper.MapToValidationResponse(result);

        // Assert
        Assert.That(response, Is.Not.Null);
        var json = JObject.FromObject(response);
        Assert.That(json["service"], Is.Not.Null);
        Assert.That(json["testSuites"], Is.Not.Null);
    }

    [Test]
    public void MapToValidationResponse_WithEmptyEndpointTests_ReturnsEmptyTestSuites()
    {
        // Arrange
        var result = new OpenApiValidationResult
        {
            IsValid = true,
            Metadata = new OpenApiValidationMetadata
            {
                BaseUrl = "https://api.example.com"
            },
            SpecificationValidation = new OpenApiSpecificationValidation
            {
                IsValid = true,
                Version = "3.0"
            },
            Summary = new OpenApiValidationSummary
            {
                TotalEndpoints = 0,
                SuccessfulTests = 0,
                FailedTests = 0
            },
            EndpointTests = new List<EndpointTestResult>()
        };

        // Act
        var response = _mapper.MapToValidationResponse(result);

        // Assert
        var json = JObject.FromObject(response);
        var testSuites = json["testSuites"] as JArray;
        Assert.That(testSuites, Is.Not.Null);
        Assert.That(testSuites, Is.Empty);
    }

    [Test]
    public void MapToValidationResponse_WithNullMetadata_HandlesGracefully()
    {
        // Arrange
        var result = new OpenApiValidationResult
        {
            IsValid = true,
            Metadata = null,
            SpecificationValidation = new OpenApiSpecificationValidation
            {
                IsValid = true
            },
            Summary = new OpenApiValidationSummary
            {
                FailedTests = 0
            },
            EndpointTests = new List<EndpointTestResult>()
        };

        // Act
        var response = _mapper.MapToValidationResponse(result);

        // Assert
        Assert.That(response, Is.Not.Null);
        var json = JObject.FromObject(response);
        Assert.That(json["service"]!["url"]!.ToString(), Is.EqualTo(""));
    }
}

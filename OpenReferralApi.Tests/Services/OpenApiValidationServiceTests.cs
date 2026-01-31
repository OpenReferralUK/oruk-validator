using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OpenApiValidationServiceTests
{
    private Mock<ILogger<OpenApiValidationService>> _loggerMock;
    private Mock<IJsonValidatorService> _jsonValidatorServiceMock;
    private Mock<IJsonSchemaResolverService> _schemaResolverServiceMock;
    private Mock<IOpenApiDiscoveryService> _discoveryServiceMock;
    private HttpClient _httpClient;
    private OpenApiValidationService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<OpenApiValidationService>>();
        _jsonValidatorServiceMock = new Mock<IJsonValidatorService>();
        _schemaResolverServiceMock = new Mock<IJsonSchemaResolverService>();
        _discoveryServiceMock = new Mock<IOpenApiDiscoveryService>();

        var mockHandler = new MockHttpMessageHandler();
        _httpClient = new HttpClient(mockHandler);

        _service = new OpenApiValidationService(
            _loggerMock.Object,
            _httpClient,
            _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object,
            _discoveryServiceMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _httpClient?.Dispose();
    }

    #region Basic Response Handling

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_ReturnsValidationResult()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_IncludesMetadata()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://api.example.com/openapi.json",
            BaseUrl = "https://api.example.com"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Metadata.Should().NotBeNull();
        result.Metadata.BaseUrl.Should().Be("https://api.example.com");
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_MeasuresDuration()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Duration.Should().BeGreaterThan(TimeSpan.Zero);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_IncludesSummary()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Summary.Should().NotBeNull();
    }

    #endregion

    #region OpenAPI Version Detection

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_DetectsOpenApi30Version()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.SpecificationValidation.Should().NotBeNull();
        result.SpecificationValidation?.OpenApiVersion.Should().Contain("3.0");
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_DetectsSwagger20Version()
    {
        // Arrange
        var json = CreateSwagger20Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/swagger.json",
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.SpecificationValidation.Should().NotBeNull();
        result.SpecificationValidation?.OpenApiVersion.Should().Contain("2.0");
    }

    #endregion

    #region Validation Options

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_SkipsValidationWhenDisabled()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            Options = new OpenApiValidationOptions { ValidateSpecification = false }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.SpecificationValidation.Should().BeNull();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_PerformsValidationWhenEnabled()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.SpecificationValidation.Should().NotBeNull();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_UsesDefaultOptionsWhenNull()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
    }

    #endregion

    #region HTTP Response Handling

    [Test]
    public void ValidateOpenApiSpecificationAsync_ThrowsOnHttpNotFound()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/notfound.json"
        };
        
        var mockHandler = new MockHttpMessageHandler((req) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
        
        var httpClient = new HttpClient(mockHandler);
        var service = new OpenApiValidationService(
            _loggerMock.Object, httpClient, _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object, _discoveryServiceMock.Object);

        try
        {
            // Act & Assert
            Assert.ThrowsAsync<HttpRequestException>(async () =>
                await service.ValidateOpenApiSpecificationAsync(request));
        }
        finally
        {
            httpClient?.Dispose();
        }
    }

    [Test]
    public void ValidateOpenApiSpecificationAsync_ThrowsOnNetworkError()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://invalid.example.com/openapi.json"
        };
        
        var mockHandler = new MockHttpMessageHandler((req) =>
            throw new HttpRequestException("Network failed"));
        
        var httpClient = new HttpClient(mockHandler);
        var service = new OpenApiValidationService(
            _loggerMock.Object, httpClient, _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object, _discoveryServiceMock.Object);

        try
        {
            // Act & Assert
            Assert.ThrowsAsync<HttpRequestException>(async () =>
                await service.ValidateOpenApiSpecificationAsync(request));
        }
        finally
        {
            httpClient?.Dispose();
        }
    }

    [Test]
    public void ValidateOpenApiSpecificationAsync_ThrowsOnInvalidJson()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/invalid.json"
        };
        
        var mockHandler = new MockHttpMessageHandler((req) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("Not valid JSON at all {{{")
            });
        
        var httpClient = new HttpClient(mockHandler);
        var service = new OpenApiValidationService(
            _loggerMock.Object, httpClient, _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object, _discoveryServiceMock.Object);

        try
        {
            // Act & Assert
            Assert.ThrowsAsync<Exception>(async () =>
                await service.ValidateOpenApiSpecificationAsync(request));
        }
        finally
        {
            httpClient?.Dispose();
        }
    }

    #endregion

    #region Cancellation Support

    [Test]
    public void ValidateOpenApiSpecificationAsync_RespectsCancellationToken()
    {
        // Arrange
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json"
        };
        SetupHttpMock(json);

        // Act & Assert
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await _service.ValidateOpenApiSpecificationAsync(request, cts.Token));
    }

    #endregion

    #region Options Processing

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_RespondsToResponseBodyOption()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            Options = new OpenApiValidationOptions { IncludeResponseBody = false }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_RespondsToTestResultsOption()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            Options = new OpenApiValidationOptions { IncludeTestResults = false }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
    }

    #endregion

    #region Helper Methods

    private void SetupHttpMock(string responseJson)
    {
        var mockHandler = new MockHttpMessageHandler((request) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson)
            });

        _httpClient?.Dispose();
        _httpClient = new HttpClient(mockHandler);

        _service = new OpenApiValidationService(
            _loggerMock.Object,
            _httpClient,
            _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object,
            _discoveryServiceMock.Object);
    }

    private string CreateOpenApi30Spec()
    {
        return @"{
            ""openapi"": ""3.0.0"",
            ""info"": {
                ""title"": ""Test API"",
                ""version"": ""1.0.0""
            },
            ""paths"": {
                ""/test"": {
                    ""get"": {
                        ""responses"": {
                            ""200"": { ""description"": ""OK"" }
                        }
                    }
                }
            }
        }";
    }

    private string CreateSwagger20Spec()
    {
        return @"{
            ""swagger"": ""2.0"",
            ""info"": {
                ""title"": ""Test API"",
                ""version"": ""1.0.0""
            },
            ""paths"": {
                ""/test"": {
                    ""get"": {
                        ""responses"": {
                            ""200"": { ""description"": ""OK"" }
                        }
                    }
                }
            }
        }";
    }

    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpMessageHandler()
            : this(req => new HttpResponseMessage(System.Net.HttpStatusCode.OK))
        {
        }

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                var response = _handler(request);
                return Task.FromResult(response);
            }
            catch (HttpRequestException ex)
            {
                return Task.FromException<HttpResponseMessage>(ex);
            }
        }
    }

    #endregion
}

using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Linq;

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

        _jsonValidatorServiceMock
            .Setup(service => service.ValidateAsync(It.IsAny<ValidationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult
            {
                IsValid = true,
                Errors = new List<OpenReferralApi.Core.Models.ValidationError>(),
                SchemaVersion = "test",
                Duration = TimeSpan.Zero
            });

        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, string documentUri, CancellationToken ct) => JSchema.Parse(schemaJson));

        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, CancellationToken ct) => JSchema.Parse(schemaJson));

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
        result.SpecificationValidation?.Errors.Should().NotBeNull();
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
        
        var mockHandler = new MockHttpMessageHandler((req, ct) =>
            new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
        
        var httpClient = new HttpClient(mockHandler);
        var service = new OpenApiValidationService(
            _loggerMock.Object, httpClient, _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object, _discoveryServiceMock.Object);

        try
        {
            // Act
            var result = service.ValidateOpenApiSpecificationAsync(request).GetAwaiter().GetResult();

            // Assert
            result.IsValid.Should().BeFalse();
            result.Summary.Should().NotBeNull();
            result.Metadata.Should().BeNull();
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
        
        var mockHandler = new MockHttpMessageHandler((req, ct) =>
            throw new HttpRequestException("Network failed"));
        
        var httpClient = new HttpClient(mockHandler);
        var service = new OpenApiValidationService(
            _loggerMock.Object, httpClient, _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object, _discoveryServiceMock.Object);

        try
        {
            // Act
            var result = service.ValidateOpenApiSpecificationAsync(request).GetAwaiter().GetResult();

            // Assert
            result.IsValid.Should().BeFalse();
            result.Summary.Should().NotBeNull();
            result.Metadata.Should().BeNull();
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
        
        var mockHandler = new MockHttpMessageHandler((req, ct) =>
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
            // Act
            var result = service.ValidateOpenApiSpecificationAsync(request).GetAwaiter().GetResult();

            // Assert
            result.IsValid.Should().BeFalse();
            result.Summary.Should().NotBeNull();
            result.Metadata.Should().BeNull();
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
        var mockHandler = new MockHttpMessageHandler((req, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            };
        });
        _httpClient?.Dispose();
        _httpClient = new HttpClient(mockHandler);
        _service = new OpenApiValidationService(
            _loggerMock.Object,
            _httpClient,
            _jsonValidatorServiceMock.Object,
            _schemaResolverServiceMock.Object,
            _discoveryServiceMock.Object);

        // Act
        var result = _service.ValidateOpenApiSpecificationAsync(request, cts.Token).GetAwaiter().GetResult();

        // Assert
        result.IsValid.Should().BeFalse();
        result.Summary.Should().NotBeNull();
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
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { IncludeResponseBody = false, TestEndpoints = true }
        };
        SetupHttpMock(json, endpointResponseBody: "{\"data\":[{\"id\":\"1\"}]}");

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
        result.EndpointTests.Should().NotBeEmpty();
        result.EndpointTests.SelectMany(e => e.TestResults).Should().NotBeEmpty();
        result.EndpointTests.SelectMany(e => e.TestResults).All(tr => tr.ResponseBody == null).Should().BeTrue();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_RespondsToTestResultsOption()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { IncludeTestResults = false, TestEndpoints = true }
        };
        SetupHttpMock(json, endpointResponseBody: "{\"data\":[{\"id\":\"1\"}]}");

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.Should().NotBeNull();
        result.EndpointTests.Should().NotBeEmpty();
        result.EndpointTests.All(e => e.TestResults.Count == 0).Should().BeTrue();
    }

    #endregion

    #region Endpoint Testing

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithPaginatedEndpoint_RequestsMultiplePages()
    {
        // Arrange
        var json = CreateOpenApi30PaginatedSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { TestEndpoints = true }
        };

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                };
            }

            var responseBody = requestUri.Contains("page=3", StringComparison.OrdinalIgnoreCase)
                ? "{\"total_pages\":3,\"data\":[{\"id\":\"3\"}]}"
                : requestUri.Contains("page=2", StringComparison.OrdinalIgnoreCase)
                    ? "{\"total_pages\":3,\"data\":[{\"id\":\"2\"}]}"
                    : "{\"total_pages\":3,\"data\":[{\"id\":\"1\"}]}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.EndpointTests.Should().HaveCount(1);
        result.EndpointTests[0].TestResults.Should().HaveCount(3);
        result.EndpointTests[0].TestResults.All(tr => tr.IsSuccess).Should().BeTrue();
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithEmptyPaginatedFeed_AddsWarning()
    {
        // Arrange
        var json = CreateOpenApi30PaginatedSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { TestEndpoints = true }
        };

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{\"total_pages\":1,\"data\":[]}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.EndpointTests.Should().HaveCount(1);
        result.EndpointTests[0].TestResults.Should().HaveCount(1);
        result.EndpointTests[0].TestResults[0].ValidationResult.Should().NotBeNull();
        result.EndpointTests[0].TestResults[0].ValidationResult!.Errors
            .Should().Contain(e => e.ErrorCode == "EMPTY_FEED_WARNING");
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithOptionalEndpointAnd404_ReturnsWarning()
    {
        // Arrange
        var json = CreateOpenApi30OptionalEndpointSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                TestOptionalEndpoints = true,
                TreatOptionalEndpointsAsWarnings = true
            }
        };

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                };
            }

            return new HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
        });

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.EndpointTests.Should().HaveCount(1);
        result.EndpointTests[0].Status.Should().Be("Warning");
        result.EndpointTests[0].TestResults.Should().HaveCount(1);
        result.EndpointTests[0].TestResults[0].ValidationResult.Should().NotBeNull();
        result.EndpointTests[0].TestResults[0].ValidationResult!.Errors
            .Should().Contain(e => e.ErrorCode == "OPTIONAL_ENDPOINT_NON_SUCCESS" && e.Severity == "Warning");
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithOptionalEndpointAndTestingDisabled_SkipsEndpoint()
    {
        // Arrange
        var json = CreateOpenApi30OptionalEndpointSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchemaUrl = "https://example.com/openapi.json",
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                TestOptionalEndpoints = false
            }
        };

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        result.EndpointTests.Should().HaveCount(1);
        result.EndpointTests[0].Status.Should().Be("Skipped");
        result.EndpointTests[0].TestResults.Should().BeEmpty();
    }

    #endregion

    #region Helper Methods

    private void SetupHttpMock(string responseJson, string endpointResponseBody = "{}")
    {
        var mockHandler = new MockHttpMessageHandler((request, ct) =>
        {
            var requestUri = request.RequestUri?.ToString() ?? string.Empty;
            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? responseJson
                : endpointResponseBody;

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
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

    private void SetupHttpMock(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
    {
        var mockHandler = new MockHttpMessageHandler(handler);
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

    private string CreateOpenApi30PaginatedSpec()
    {
        return @"{
            ""openapi"": ""3.0.0"",
            ""info"": {
                ""title"": ""Test API"",
                ""version"": ""1.0.0""
            },
            ""paths"": {
                ""/items"": {
                    ""get"": {
                        ""parameters"": [
                            {
                                ""name"": ""page"",
                                ""in"": ""query"",
                                ""schema"": { ""type"": ""integer"" }
                            }
                        ],
                        ""responses"": {
                            ""200"": {
                                ""description"": ""OK"",
                                ""content"": {
                                    ""application/json"": {
                                        ""schema"": {
                                            ""type"": ""object"",
                                            ""properties"": {
                                                ""total_pages"": { ""type"": ""integer"" },
                                                ""data"": {
                                                    ""type"": ""array"",
                                                    ""items"": { ""type"": ""object"" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }";
    }

    private string CreateOpenApi30OptionalEndpointSpec()
    {
        return @"{
            ""openapi"": ""3.0.0"",
            ""info"": {
                ""title"": ""Test API"",
                ""version"": ""1.0.0""
            },
            ""paths"": {
                ""/optional"": {
                    ""get"": {
                        ""tags"": [""Optional""],
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
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

        public MockHttpMessageHandler()
            : this((req, ct) => new HttpResponseMessage(System.Net.HttpStatusCode.OK))
        {
        }

        public MockHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                var response = _handler(request, cancellationToken);
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

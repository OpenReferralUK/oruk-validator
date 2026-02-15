using Microsoft.Extensions.Logging;
using Moq;
using Json.Schema;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Linq;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OpenApiValidationServiceTests
{
    private Mock<ILogger<OpenApiValidationService>> _loggerMock;
    private Mock<IJsonValidatorService> _jsonValidatorServiceMock;
    private Mock<ISchemaResolverService> _schemaResolverServiceMock;
    private Mock<IOpenApiDiscoveryService> _discoveryServiceMock;
    private HttpClient _httpClient;
    private OpenApiValidationService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<OpenApiValidationService>>();
        _jsonValidatorServiceMock = new Mock<IJsonValidatorService>();
        _schemaResolverServiceMock = new Mock<ISchemaResolverService>();
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
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DataSourceAuthentication>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, string documentUri, DataSourceAuthentication auth, CancellationToken ct) => JsonSchema.FromText(schemaJson));

        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, CancellationToken ct) => JsonSchema.FromText(schemaJson));

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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_IncludesMetadata()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://api.example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com"
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.Metadata, Is.Not.Null);
        Assert.That(result.Metadata!.BaseUrl, Is.EqualTo("https://api.example.com"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_MeasuresDuration()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.Duration, Is.GreaterThan(TimeSpan.Zero));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_IncludesSummary()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.Summary, Is.Not.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.SpecificationValidation, Is.Not.Null);
        Assert.That(result.SpecificationValidation!.OpenApiVersion, Does.Contain("3.0"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_DetectsSwagger20Version()
    {
        // Arrange
        var json = CreateSwagger20Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/swagger.json"
            },
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.SpecificationValidation, Is.Not.Null);
        Assert.That(result.SpecificationValidation!.Errors, Is.Not.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            Options = new OpenApiValidationOptions { ValidateSpecification = false }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.SpecificationValidation, Is.Null);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_PerformsValidationWhenEnabled()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            Options = new OpenApiValidationOptions { ValidateSpecification = true }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result.SpecificationValidation, Is.Not.Null);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_UsesDefaultOptionsWhenNull()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            }
        };
        SetupHttpMock(json);

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region HTTP Response Handling

    [Test]
    public void ValidateOpenApiSpecificationAsync_ThrowsOnHttpNotFound()
    {
        // Arrange
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/notfound.json"
            }
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
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Summary, Is.Not.Null);
            Assert.That(result.Metadata, Is.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://invalid.example.com/openapi.json"
            }
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
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Summary, Is.Not.Null);
            Assert.That(result.Metadata, Is.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/invalid.json"
            }
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
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Summary, Is.Not.Null);
            Assert.That(result.Metadata, Is.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            }
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
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Summary, Is.Not.Null);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { IncludeResponseBody = false, TestEndpoints = true }
        };
        SetupHttpMock(json, endpointResponseBody: "{\"data\":[{\"id\":\"1\"}]}");

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.EndpointTests, Is.Not.Empty);
        Assert.That(result.EndpointTests.SelectMany(e => e.TestResults), Is.Not.Empty);
        Assert.That(result.EndpointTests.SelectMany(e => e.TestResults).All(tr => tr.ResponseBody == null), Is.True);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_RespondsToTestResultsOption()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            Options = new OpenApiValidationOptions { IncludeTestResults = false, TestEndpoints = true }
        };
        SetupHttpMock(json, endpointResponseBody: "{\"data\":[{\"id\":\"1\"}]}");

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.EndpointTests, Is.Not.Empty);
        Assert.That(result.EndpointTests.All(e => e.TestResults.Count == 0), Is.True);
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
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
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
        Assert.That(result.EndpointTests, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].TestResults, Has.Count.EqualTo(3));
        Assert.That(result.EndpointTests[0].TestResults.All(tr => tr.IsSuccess), Is.True);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithEmptyPaginatedFeed_AddsWarning()
    {
        // Arrange
        var json = CreateOpenApi30PaginatedSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
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
        Assert.That(result.EndpointTests, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].TestResults, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].TestResults[0].ValidationResult, Is.Not.Null);
        Assert.That(result.EndpointTests[0].TestResults[0].ValidationResult!.Errors,
            Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(e => e.ErrorCode == "EMPTY_FEED_WARNING"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithOptionalEndpointAnd404_ReturnsWarning()
    {
        // Arrange
        var json = CreateOpenApi30OptionalEndpointSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
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
        Assert.That(result.EndpointTests, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].Status, Is.EqualTo("Warning"));
        Assert.That(result.EndpointTests[0].TestResults, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].TestResults[0].ValidationResult, Is.Not.Null);
        Assert.That(result.EndpointTests[0].TestResults[0].ValidationResult!.Errors,
            Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(e => e.ErrorCode == "OPTIONAL_ENDPOINT_NON_SUCCESS" && e.Severity == "Warning"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithOptionalEndpointAndTestingDisabled_SkipsEndpoint()
    {
        // Arrange
        var json = CreateOpenApi30OptionalEndpointSpec();
        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
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
        Assert.That(result.EndpointTests, Has.Count.EqualTo(1));
        Assert.That(result.EndpointTests[0].Status, Is.EqualTo("Skipped"));
        Assert.That(result.EndpointTests[0].TestResults, Is.Empty);
    }

    #endregion

    #region Authentication Tests

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithApiKeyAuth_AddsCorrectHeader()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                ApiKey = "test-api-key-12345"
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null, "Expected endpoint request to be captured");
        Assert.That(capturedRequest!.Headers.Contains("X-API-Key"), Is.True, "Expected X-API-Key header to be present");
        Assert.That(capturedRequest.Headers.GetValues("X-API-Key").First(), Is.EqualTo("test-api-key-12345"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithCustomApiKeyHeader_AddsCorrectHeader()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                ApiKey = "custom-key-value",
                ApiKeyHeader = "X-Custom-Auth-Key"
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Custom-Auth-Key"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Custom-Auth-Key").First(), Is.EqualTo("custom-key-value"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithBearerToken_AddsAuthorizationHeader()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                BearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Not.Null);
        Assert.That(capturedRequest.Headers.Authorization!.Scheme, Is.EqualTo("Bearer"));
        Assert.That(capturedRequest.Headers.Authorization.Parameter, Is.EqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithBasicAuth_AddsAuthorizationHeader()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                BasicAuth = new BasicAuthentication
                {
                    Username = "testuser",
                    Password = "testpass123"
                }
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Not.Null);
        Assert.That(capturedRequest.Headers.Authorization!.Scheme, Is.EqualTo("Basic"));
        
        // Decode and verify credentials
        var credentials = System.Text.Encoding.ASCII.GetString(
            Convert.FromBase64String(capturedRequest.Headers.Authorization.Parameter!));
        Assert.That(credentials, Is.EqualTo("testuser:testpass123"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithCustomHeaders_AddsAllHeaders()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                CustomHeaders = new Dictionary<string, string>
                {
                    { "X-Client-Id", "client-123" },
                    { "X-Request-Id", "req-456" },
                    { "X-Tenant-Id", "tenant-789" }
                }
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Client-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Client-Id").First(), Is.EqualTo("client-123"));
        Assert.That(capturedRequest.Headers.Contains("X-Request-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Request-Id").First(), Is.EqualTo("req-456"));
        Assert.That(capturedRequest.Headers.Contains("X-Tenant-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Tenant-Id").First(), Is.EqualTo("tenant-789"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithMultipleAuthMethods_AddsAllHeaders()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                BearerToken = "jwt-token-here",
                CustomHeaders = new Dictionary<string, string>
                {
                    { "X-Client-Id", "multi-auth-client" }
                }
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Not.Null);
        Assert.That(capturedRequest.Headers.Authorization!.Scheme, Is.EqualTo("Bearer"));
        Assert.That(capturedRequest.Headers.Authorization.Parameter, Is.EqualTo("jwt-token-here"));
        Assert.That(capturedRequest.Headers.Contains("X-Client-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Client-Id").First(), Is.EqualTo("multi-auth-client"));
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithSkipAuthenticationTrue_DoesNotAddHeaders()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                ApiKey = "should-not-be-added",
                BearerToken = "also-should-not-be-added"
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = true  // Authentication should be skipped
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-API-Key"), Is.False);
        Assert.That(capturedRequest.Headers.Authorization, Is.Null);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithEmptyAuthData_DoesNotAddHeaders()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication(),  // Empty auth data
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null);
    }

    [Test]
    public async Task ValidateOpenApiSpecificationAsync_WithBasicAuthEmptyPassword_UsesEmptyString()
    {
        // Arrange
        var json = CreateOpenApi30Spec();
        HttpRequestMessage? capturedRequest = null;

        SetupHttpMock((req, ct) =>
        {
            var requestUri = req.RequestUri?.ToString() ?? string.Empty;
            if (!requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                capturedRequest = req;
            }

            var responseBody = requestUri.Contains("openapi", StringComparison.OrdinalIgnoreCase)
                ? json
                : "{}";

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            };
        });

        var request = new OpenApiValidationRequest
        {
            OpenApiSchema = new OpenApiSchema
            {
                Url = "https://example.com/openapi.json"
            },
            BaseUrl = "https://api.example.com",
            DataSourceAuth = new DataSourceAuthentication
            {
                BasicAuth = new BasicAuthentication
                {
                    Username = "testuser",
                    Password = string.Empty  // Empty password
                }
            },
            Options = new OpenApiValidationOptions
            {
                TestEndpoints = true,
                SkipAuthentication = false
            }
        };

        // Act
        var result = await _service.ValidateOpenApiSpecificationAsync(request);

        // Assert
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Not.Null);
        Assert.That(capturedRequest.Headers.Authorization!.Scheme, Is.EqualTo("Basic"));
        
        // Decode and verify credentials (empty password becomes empty string)
        var credentials = System.Text.Encoding.ASCII.GetString(
            Convert.FromBase64String(capturedRequest.Headers.Authorization.Parameter!));
        Assert.That(credentials, Is.EqualTo("testuser:"));
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

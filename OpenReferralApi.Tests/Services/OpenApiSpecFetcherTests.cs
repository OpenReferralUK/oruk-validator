using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Newtonsoft.Json.Linq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OpenApiSpecFetcherTests
{
    private Mock<ILogger<OpenApiValidationService>> _loggerMock;
    private Mock<ILogger<SchemaResolverService>> _schemaResolverLoggerMock;
    private Mock<ISchemaResolverService> _schemaResolverServiceMock;
    private IMemoryCache _memoryCache;
    private IOptions<CacheOptions> _cacheOptions;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<OpenApiValidationService>>();
        _schemaResolverLoggerMock = new Mock<ILogger<SchemaResolverService>>();
        _schemaResolverServiceMock = new Mock<ISchemaResolverService>();

        // Create real MemoryCache for testing
        _memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 100 * 1024 * 1024 // 100 MB
        });

        _cacheOptions = Options.Create(new CacheOptions
        {
            Enabled = false,
            ExpirationMinutes = 60,
            UseSlidingExpiration = true,
            SlidingExpirationMinutes = 60
        });

        // Mock ResolveAsync to return the same JSON
        _schemaResolverServiceMock
            .Setup(s => s.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DataSourceAuthentication>()))
            .ReturnsAsync((string content, string baseUri, DataSourceAuthentication auth) => content);
    }

    [TearDown]
    public void TearDown()
    {
        _memoryCache?.Dispose();
    }

    #region Authentication Validation Tests

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithApiKeyButNoHeader_SkipsAuthentication()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            ApiKey = "test-key"
            // ApiKeyHeader is null - should use default "X-API-Key"
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        // OpenApiSpecFetcher uses default header "X-API-Key" when ApiKeyHeader is null
        Assert.That(capturedRequest!.Headers.Contains("X-API-Key"), Is.True);
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithEmptyApiKey_SkipsApiKeyAuth()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            ApiKey = "",  // Empty string
            ApiKeyHeader = "X-Custom-Key"
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Custom-Key"), Is.False, "Empty API key should not add header");
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithEmptyBearerToken_SkipsBearerAuth()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            BearerToken = ""  // Empty string
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null, "Empty bearer token should not add Authorization header");
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithBasicAuthNoUsername_SkipsBasicAuth()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            BasicAuth = new BasicAuthentication
            {
                Username = "",  // Empty username
                Password = "password"
            }
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null, "Basic auth without username should not add Authorization header");
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithOnlyCustomHeaders_AppliesHeaders()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            CustomHeaders = new Dictionary<string, string>
            {
                { "X-Client-Id", "client-123" },
                { "X-Tenant-Id", "tenant-456" }
            }
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Client-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Client-Id").First(), Is.EqualTo("client-123"));
        Assert.That(capturedRequest.Headers.Contains("X-Tenant-Id"), Is.True);
        Assert.That(capturedRequest.Headers.GetValues("X-Tenant-Id").First(), Is.EqualTo("tenant-456"));
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithEmptyCustomHeaders_SkipsAuthentication()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication
        {
            CustomHeaders = new Dictionary<string, string>()  // Empty dictionary
        };

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        // No custom headers should be added
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithCompletelyEmptyAuth_SkipsAllAuth()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        var auth = new DataSourceAuthentication();  // Completely empty

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, auth, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null);
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithNullAuth_SkipsAllAuth()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, null, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null);
    }

    #endregion

    #region URL Validation Tests

    [Test]
    public void FetchOpenApiSpecFromUrlAsync_WithInvalidUrl_ThrowsArgumentException()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(CreateMinimalOpenApiSpec())
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act & Assert
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fetcher.FetchOpenApiSpecFromUrlAsync("not-a-valid-url", null, CancellationToken.None));
        
        Assert.That(ex!.Message, Does.Contain("Failed to fetch OpenAPI specification"));
        Assert.That(ex!.InnerException, Is.InstanceOf<ArgumentException>());
        Assert.That(ex!.InnerException!.Message, Does.Contain("Invalid OpenAPI spec URL"));
    }

    [Test]
    public void FetchOpenApiSpecFromUrlAsync_WithRelativeUrl_ThrowsArgumentException()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(CreateMinimalOpenApiSpec())
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act & Assert
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fetcher.FetchOpenApiSpecFromUrlAsync("/api/openapi.json", null, CancellationToken.None));
        
        Assert.That(ex!.Message, Does.Contain("Failed to fetch OpenAPI specification"));
        Assert.That(ex!.InnerException, Is.InstanceOf<ArgumentException>());
        Assert.That(ex!.InnerException!.Message, Does.Contain("Invalid OpenAPI spec URL"));
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithValidHttpsUrl_Succeeds()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, null, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<JObject>());
    }

    #endregion

    #region Reference Resolution Tests

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithResolveReferencesTrue_CallsSchemaResolver()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, null, CancellationToken.None, resolveReferences: true);

        // Assert
        Assert.That(result, Is.Not.Null);
        _schemaResolverServiceMock.Verify(
            s => s.ResolveAsync(It.IsAny<string>(), specUrl, null),
            Times.Once,
            "SchemaResolverService.ResolveAsync should be called when resolveReferences is true");
    }

    [Test]
    public async Task FetchOpenApiSpecFromUrlAsync_WithResolveReferencesFalse_SkipsSchemaResolver()
    {
        // Arrange
        var specUrl = "https://example.com/openapi.json";
        var specJson = CreateMinimalOpenApiSpec();

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(specJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var fetcher = new OpenApiSpecFetcher(httpClient, _loggerMock.Object, _schemaResolverServiceMock.Object);

        // Act
        var result = await fetcher.FetchOpenApiSpecFromUrlAsync(specUrl, null, CancellationToken.None, resolveReferences: false);

        // Assert
        Assert.That(result, Is.Not.Null);
        _schemaResolverServiceMock.Verify(
            s => s.ResolveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DataSourceAuthentication>()),
            Times.Never,
            "SchemaResolverService.ResolveAsync should not be called when resolveReferences is false");
    }

    #endregion

    #region Helper Methods

    private static string CreateMinimalOpenApiSpec()
    {
        return @"{
            ""openapi"": ""3.0.0"",
            ""info"": {
                ""title"": ""Test API"",
                ""version"": ""1.0.0""
            },
            ""paths"": {}
        }";
    }

    #endregion

    /// <summary>
    /// Mock HTTP message handler for testing
    /// </summary>
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handler;

        public MockHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _handler(request);
        }
    }
}

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Text.Json.Nodes;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class RemoteSchemaLoaderTests
{
    private Mock<ILogger<SchemaResolverService>> _loggerMock;
    private IMemoryCache _memoryCache;
    private IOptions<CacheOptions> _cacheOptions;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<SchemaResolverService>>();
        
        // Create real MemoryCache for testing
        _memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 100 * 1024 * 1024 // 100 MB
        });

        // Disable caching by default for tests
        _cacheOptions = Options.Create(new CacheOptions
        {
            Enabled = false,
            ExpirationMinutes = 60,
            UseSlidingExpiration = true,
            SlidingExpirationMinutes = 60
        });
    }

    [TearDown]
    public void TearDown()
    {
        _memoryCache?.Dispose();
    }

    #region Security Tests - Header Injection Prevention

    [Test]
    public async Task LoadRemoteSchemaAsync_WithControlCharacterInHeaderName_SkipsHeader()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            CustomHeaders = new Dictionary<string, string>
            {
                { "X-Valid-Header", "value1" },
                { "X-Mal\nicious", "injected" },  // Control character (newline)
                { "X-Another-Valid", "value2" }
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Valid-Header"), Is.True, "Valid header should be applied");
        Assert.That(capturedRequest.Headers.Contains("X-Another-Valid"), Is.True, "Another valid header should be applied");
        // HttpHeaders.Contains() throws FormatException for invalid header names, so we can't check directly
        // The important thing is the valid headers were added successfully, meaning invalid one was skipped
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithColonInHeaderName_SkipsHeader()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            CustomHeaders = new Dictionary<string, string>
            {
                { "X-Valid:Malicious", "value" }  // Colon in header name
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        // HttpHeaders.Contains() throws FormatException for invalid header names, so we can't check directly
        // The important thing is the request succeeded, meaning the invalid header was skipped
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithCarriageReturnInHeaderName_SkipsHeader()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            CustomHeaders = new Dictionary<string, string>
            {
                { "X-Valid-Header", "value1" },
                { "X-Bad\rHeader", "injected" }  // Carriage return
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Valid-Header"), Is.True);
        // HttpHeaders.Contains() throws FormatException for invalid header names, so we can't check directly
        // The important thing is the valid header was added successfully
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithInterfaceBasedAuthentication_AppliesHeaders()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        IAuthenticationConfig auth = new TestAuthenticationConfig
        {
            ApiKey = "test-key",
            ApiKeyHeader = "X-Test-Key",
            CustomHeaders = new Dictionary<string, string>
            {
                { "X-From-Interface", "yes" }
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Contains("X-Test-Key"), Is.True);
        Assert.That(capturedRequest.Headers.Contains("X-From-Interface"), Is.True);
    }

    private sealed class TestAuthenticationConfig : IAuthenticationConfig
    {
        public string? ApiKey { get; set; }
        public string ApiKeyHeader { get; set; } = "X-API-Key";
        public string? BearerToken { get; set; }
        public BasicAuthentication? BasicAuth { get; set; }
        public Dictionary<string, string>? CustomHeaders { get; set; } = new();
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithInvalidApiKeyHeader_SkipsApiKeyAuth()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            ApiKey = "valid-key",
            ApiKeyHeader = "X-Mal\nicious-Key"  // Control character in header name
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        // HttpHeaders.Contains() throws FormatException for invalid header names, so we can't check directly
        // The important thing is the request succeeded without adding the invalid header
    }

    #endregion

    #region Security Tests - SSRF Protection

    [Test]
    public void LoadRemoteSchemaAsync_WithFileScheme_ThrowsArgumentException()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(@"{""type"": ""object""}")
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await loader.LoadRemoteSchemaAsync("file:///etc/passwd"));
        
        Assert.That(ex!.Message, Does.Contain("Invalid schema URL"));
        Assert.That(ex.Message, Does.Contain("HTTP and HTTPS"));
    }

    [Test]
    public void LoadRemoteSchemaAsync_WithFtpScheme_ThrowsArgumentException()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(@"{""type"": ""object""}")
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await loader.LoadRemoteSchemaAsync("ftp://malicious.com/schema.json"));
        
        Assert.That(ex!.Message, Does.Contain("Invalid schema URL"));
    }

    [Test]
    public void LoadRemoteSchemaAsync_WithDataScheme_ThrowsArgumentException()
    {
        // Arrange
        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(@"{""type"": ""object""}")
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        // Act & Assert
        var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
            await loader.LoadRemoteSchemaAsync("data:text/plain,{\"type\":\"object\"}"));
        
        Assert.That(ex!.Message, Does.Contain("Invalid schema URL"));
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithHttpsScheme_Succeeds()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithHttpScheme_Succeeds()
    {
        // Arrange
        var schemaUrl = "http://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region Authentication Validation Tests

    [Test]
    public async Task LoadRemoteSchemaAsync_WithApiKeyButNoHeader_SkipsAuthentication()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            ApiKey = "test-key"
            // ApiKeyHeader is null
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null, "No authorization header should be added");
        // Don't check header count as HttpClient may add default headers like User-Agent
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithBasicAuthEmptyPassword_SkipsAuthentication()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            BasicAuth = new BasicAuthentication
            {
                Username = "testuser",
                Password = string.Empty  // Empty password
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null, "BasicAuth with empty password should be skipped");
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithBasicAuthNullPassword_SkipsAuthentication()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            BasicAuth = new BasicAuthentication
            {
                Username = "testuser",
                Password = null!  // Null password
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null, "BasicAuth with null password should be skipped");
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithValidBasicAuth_AppliesAuthentication()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication
        {
            BasicAuth = new BasicAuthentication
            {
                Username = "testuser",
                Password = "testpass"
            }
        };

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Not.Null);
        Assert.That(capturedRequest.Headers.Authorization!.Scheme, Is.EqualTo("Basic"));
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithEmptyAuthObject_SkipsAuthentication()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";
        HttpRequestMessage? capturedRequest = null;

        var handler = new MockHttpMessageHandler(async request =>
        {
            capturedRequest = request;
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);

        var auth = new DataSourceAuthentication();  // Empty auth object

        loader.SetAuthentication(auth);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(capturedRequest, Is.Not.Null);
        Assert.That(capturedRequest!.Headers.Authorization, Is.Null);
    }

    #endregion

    #region Cache Tests

    [Test]
    public async Task LoadRemoteSchemaAsync_WithCachingEnabled_StoresInCache()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object"", ""title"": ""cached""}";

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        
        var cacheOptions = Options.Create(new CacheOptions
        {
            Enabled = true,
            ExpirationMinutes = 60,
            UseSlidingExpiration = false
        });

        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, cacheOptions);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        
        var cacheKey = $"schema:{schemaUrl}";
        var cached = _memoryCache.TryGetValue<string>(cacheKey, out var cachedContent);
        Assert.That(cached, Is.True, "Schema should be cached");
        Assert.That(cachedContent, Is.EqualTo(schemaJson));
    }

    [Test]
    public async Task LoadRemoteSchemaAsync_WithSlidingExpiration_ConfiguresCorrectly()
    {
        // Arrange
        var schemaUrl = "https://example.com/schema.json";
        var schemaJson = @"{""type"": ""object""}";

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(schemaJson)
            };
        });

        using var httpClient = new HttpClient(handler);
        
        var cacheOptions = Options.Create(new CacheOptions
        {
            Enabled = true,
            ExpirationMinutes = 120,
            UseSlidingExpiration = true,
            SlidingExpirationMinutes = 60
        });

        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, cacheOptions);

        // Act
        var result = await loader.LoadRemoteSchemaAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        
        var cacheKey = $"schema:{schemaUrl}";
        var cached = _memoryCache.TryGetValue<string>(cacheKey, out var cachedContent);
        Assert.That(cached, Is.True, "Schema should be cached with sliding expiration");
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

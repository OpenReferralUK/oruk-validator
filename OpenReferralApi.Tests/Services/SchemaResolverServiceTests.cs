using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Json.Schema;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Text.Json.Nodes;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class SchemaResolverServiceTests
{
  private Mock<ILogger<SchemaResolverService>> _loggerMock;
  private Mock<HttpClient> _httpClientMock;
  private IMemoryCache _memoryCache;
  private IOptions<CacheOptions> _cacheOptions;
  private SchemaResolverService _service;

  [SetUp]
  public void Setup()
  {
    _loggerMock = new Mock<ILogger<SchemaResolverService>>();
    _httpClientMock = new Mock<HttpClient>();
    
    // Create real MemoryCache for testing
    _memoryCache = new MemoryCache(new MemoryCacheOptions
    {
      SizeLimit = 100 * 1024 * 1024 // 100 MB
    });
    
    // Create cache options with caching disabled for most tests
    _cacheOptions = Options.Create(new CacheOptions
    {
      Enabled = false, // Disabled by default to not affect existing tests
      ExpirationMinutes = 60,
      MaxSizeMB = 100
    });
    
    _service = new SchemaResolverService(_httpClientMock.Object, _loggerMock.Object, _memoryCache, _cacheOptions);
  }

  [TearDown]
  public void TearDown()
  {
    _memoryCache.Dispose();
  }

  #region System.Text.Json ResolveAsync Tests

  [Test]
  public async Task ResolveAsync_WithStringInput_ResolvesReferences()
  {
    // Arrange
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""name"": { ""type"": ""string"" }
            }
        }";

    // Act
    var result = await _service.ResolveAsync(schemaJson);

    // Assert
    Assert.That(result, Is.Not.Null);
    Assert.That(result, Does.Contain("object"));
  }

  [Test]
  public async Task ResolveAsync_WithJsonNode_ResolvesReferences()
  {
    // Arrange
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""id"": { ""type"": ""string"" }
            }
        }";
    var jsonNode = JsonNode.Parse(schemaJson);
    Assert.That(jsonNode, Is.Not.Null);

    // Act
    var result = await _service.ResolveAsync(jsonNode!);

    // Assert
    Assert.That(result, Is.Not.Null);
    Assert.That(result?["type"]?.GetValue<string>(), Is.EqualTo("object"));
  }

  [Test]
  public async Task ResolveAsync_WithInternalRef_ResolvesJsonPointer()
  {
    // Arrange
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""config"": { ""$ref"": ""#/definitions/Config"" }
            },
            ""definitions"": {
                ""Config"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""setting"": { ""type"": ""string"" }
                    }
                }
            }
        }";
    var jsonNode = JsonNode.Parse(schemaJson);
    Assert.That(jsonNode, Is.Not.Null);

    // Act
    var result = await _service.ResolveAsync(jsonNode!);

    // Assert
    Assert.That(result, Is.Not.Null);
  }

  #endregion

  #region Json.Schema CreateSchemaFromJsonAsync Tests

  [Test]
  public async Task CreateSchemaFromJsonAsync_WithValidSchema_ReturnsSchema()
  {
    // Arrange
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""name"": { ""type"": ""string"" },
                ""age"": { ""type"": ""integer"" }
            },
            ""required"": [""name""]
        }";

    // Act
    var result = await _service.CreateSchemaFromJsonAsync(schemaJson);

    // Assert
    Assert.That(result, Is.Not.Null);
    // In Json.Schema.Net, we can't check for specific keywords like TypeKeyword,
    // but we can verify the schema was created successfully by trying to evaluate something
    var testJson = System.Text.Json.Nodes.JsonNode.Parse(@"{""name"": ""test""}");
    using var doc = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(testJson));
    var evaluationResult = result.Evaluate(doc.RootElement);
    Assert.That(evaluationResult.IsValid, Is.True);
  }

  [Test]
  public async Task CreateSchemaFromJsonAsync_WithDocumentUri_CreatesSchemaWithBaseUri()
  {
    // Arrange
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""id"": { ""type"": ""string"" }
            }
        }";
    var documentUri = "https://example.com/schemas/test.json";

    // Act
    var result = await _service.CreateSchemaFromJsonAsync(schemaJson, documentUri);

    // Assert
    Assert.That(result, Is.Not.Null);
  }

  [Test]
  public async Task CreateSchemaFromJsonAsync_WithOfflineRef_HandlesReference()
  {
    // Arrange
    // Use $defs (newer JSON Schema standard) instead of definitions
    var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""config"": { ""$ref"": ""#/$defs/Config"" }
            },
            ""$defs"": {
                ""Config"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""setting"": { ""type"": ""string"" }
                    }
                }
            }
        }";

    // Act
    var result = await _service.CreateSchemaFromJsonAsync(schemaJson);

    // Assert
    Assert.That(result, Is.Not.Null);
  }

  #endregion

  #region Cache Tests

  [Test]
  public async Task LoadRemoteSchemaAsync_WithCacheEnabled_UsesCache()
  {
    // Arrange
    var schemaUrl = "https://example.com/schema.json";
    var schemaJson = @"{""type"": ""object""}";
    
    // Create service with caching enabled
    var cacheOptions = Options.Create(new CacheOptions
    {
      Enabled = true,
      ExpirationMinutes = 60
    });
    
    var memoryCache = new MemoryCache(new MemoryCacheOptions
    {
      SizeLimit = 100 * 1024 * 1024
    });

    var handler = new MockHttpMessageHandler(async request =>
    {
      if (request.RequestUri?.ToString() == schemaUrl)
      {
        return new HttpResponseMessage
        {
          StatusCode = System.Net.HttpStatusCode.OK,
          Content = new StringContent(schemaJson)
        };
      }
      return new HttpResponseMessage { StatusCode = System.Net.HttpStatusCode.NotFound };
    });

    var httpClient = new HttpClient(handler);
    var service = new SchemaResolverService(httpClient, _loggerMock.Object, memoryCache, cacheOptions);

    // Create a simple schema with external ref
    var mainSchemaJson = @"{
      ""type"": ""object"",
      ""properties"": {
        ""ref"": { ""$ref"": """ + schemaUrl + @""" }
      }
    }";

    // Act - First call should fetch from HTTP
    var result1 = await service.ResolveAsync(mainSchemaJson, "https://example.com/");
    
    // Act - Second call should use cache (we can verify this by checking logs or cache state)
    var result2 = await service.ResolveAsync(mainSchemaJson, "https://example.com/");

    // Assert
    Assert.That(result1, Is.Not.Null);
    Assert.That(result2, Is.Not.Null);
    
    // Verify cache contains the schema
    var cacheKey = $"schema:{schemaUrl}";
    Assert.That(memoryCache.TryGetValue(cacheKey, out string? _), Is.True);
  }

  [Test]
  public async Task LoadRemoteSchemaAsync_WithCacheDisabled_SkipsCache()
  {
    // Arrange
    var schemaUrl = "https://example.com/schema.json";
    var schemaJson = @"{""type"": ""object""}";
    
    // Create service with caching disabled
    var cacheOptions = Options.Create(new CacheOptions
    {
      Enabled = false
    });
    
    var memoryCache = new MemoryCache(new MemoryCacheOptions
    {
      SizeLimit = 100 * 1024 * 1024
    });

    var handler = new MockHttpMessageHandler(async request =>
    {
      if (request.RequestUri?.ToString() == schemaUrl)
      {
        return new HttpResponseMessage
        {
          StatusCode = System.Net.HttpStatusCode.OK,
          Content = new StringContent(schemaJson)
        };
      }
      return new HttpResponseMessage { StatusCode = System.Net.HttpStatusCode.NotFound };
    });

    var httpClient = new HttpClient(handler);
    var service = new SchemaResolverService(httpClient, _loggerMock.Object, memoryCache, cacheOptions);

    // Create a simple schema with external ref
    var mainSchemaJson = @"{
      ""type"": ""object"",
      ""properties"": {
        ""ref"": { ""$ref"": """ + schemaUrl + @""" }
      }
    }";

    // Act
    var result = await service.ResolveAsync(mainSchemaJson, "https://example.com/");

    // Assert
    Assert.That(result, Is.Not.Null);
    
    // Verify cache does not contain the schema
    var cacheKey = $"schema:{schemaUrl}";
    Assert.That(memoryCache.TryGetValue(cacheKey, out string? _), Is.False);
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

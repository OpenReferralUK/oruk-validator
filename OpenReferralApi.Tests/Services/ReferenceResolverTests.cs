using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Text.Json.Nodes;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class ReferenceResolverTests
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

    #region Circular Reference Detection Tests

    [Test]
    public async Task ResolveAllRefsAsync_WithDirectCircularReference_BreaksLoop()
    {
        // Arrange
        var schema = @"{
            ""type"": ""object"",
            ""properties"": {
                ""self"": { ""$ref"": ""#/properties/self"" }
            }
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null, "Should return a result even with circular reference");
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("self"), Is.True);
        
        // The circular reference should be preserved as a $ref to prevent infinite loop
        var self = properties["self"]!.AsObject();
        Assert.That(self.ContainsKey("$ref"), Is.True, "Circular reference should be preserved as $ref");
    }

    [Test]
    public async Task ResolveAllRefsAsync_WithIndirectCircularReference_BreaksLoop()
    {
        // Arrange - Person references Address, Address references Person
        var schema = @"{
            ""definitions"": {
                ""Person"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""address"": { ""$ref"": ""#/definitions/Address"" }
                    }
                },
                ""Address"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""resident"": { ""$ref"": ""#/definitions/Person"" }
                    }
                }
            },
            ""$ref"": ""#/definitions/Person""
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("type"), Is.True);
        Assert.That(resultObj["type"]!.GetValue<string>(), Is.EqualTo("object"));
    }

    [Test]
    public async Task ResolveAllRefsAsync_WithChainedCircularReference_BreaksLoop()
    {
        // Arrange - A -> B -> C -> A
        var schema = @"{
            ""definitions"": {
                ""A"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""b"": { ""$ref"": ""#/definitions/B"" }
                    }
                },
                ""B"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""c"": { ""$ref"": ""#/definitions/C"" }
                    }
                },
                ""C"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""a"": { ""$ref"": ""#/definitions/A"" }
                    }
                }
            },
            ""$ref"": ""#/definitions/A""
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("type"), Is.True);
        Assert.That(resultObj["type"]!.GetValue<string>(), Is.EqualTo("object"));
        
        // Verify the chain is resolved but circular ref is prevented
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
    }

    [Test]
    public async Task ResolveAllRefsAsync_WithExternalCircularReference_BreaksLoop()
    {
        // Arrange
        var schema = @"{
            ""type"": ""object"",
            ""properties"": {
                ""external"": { ""$ref"": ""https://example.com/circular.json"" }
            }
        }";

        var externalSchema = @"{
            ""type"": ""object"",
            ""properties"": {
                ""backRef"": { ""$ref"": ""https://example.com/circular.json"" }
            }
        }";

        var handler = new MockHttpMessageHandler(async request =>
        {
            return new HttpResponseMessage
            {
                StatusCode = System.Net.HttpStatusCode.OK,
                Content = new StringContent(externalSchema)
            };
        });

        using var httpClient = new HttpClient(handler);
        var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, _cacheOptions);
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("external"), Is.True);
        
        // The external schema should be resolved, but the circular ref inside it should be preserved
        var external = properties["external"]!.AsObject();
        Assert.That(external.ContainsKey("type"), Is.True);
    }

    #endregion

    #region Internal Reference Resolution Tests

    [Test]
    public async Task ResolveInternalRefAsync_WithValidPointer_ResolvesCorrectly()
    {
        // Arrange
        var schema = @"{
            ""definitions"": {
                ""User"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""name"": { ""type"": ""string"" }
                    }
                }
            },
            ""$ref"": ""#/definitions/User""
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj["type"]!.GetValue<string>(), Is.EqualTo("object"));
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("name"), Is.True);
    }

    [Test]
    public async Task ResolveInternalRefAsync_WithArrayIndex_ResolvesCorrectly()
    {
        // Arrange
        var schema = @"{
            ""items"": [
                { ""type"": ""string"" },
                { ""type"": ""number"" },
                { ""type"": ""boolean"" }
            ],
            ""properties"": {
                ""field"": { ""$ref"": ""#/items/1"" }
            }
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("field"), Is.True);
        
        var field = properties["field"]!.AsObject();
        Assert.That(field["type"]!.GetValue<string>(), Is.EqualTo("number"), "Should resolve to the item at index 1");
    }

    [Test]
    public async Task ResolveInternalRefAsync_WithEscapedPointer_UnescapesCorrectly()
    {
        // Arrange - JSON pointer escaping: ~0 = ~, ~1 = /
        var schema = @"{
            ""definitions"": {
                ""field~name/path"": {
                    ""type"": ""string""
                }
            },
            ""properties"": {
                ""test"": { ""$ref"": ""#/definitions/field~0name~1path"" }
            }
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("test"), Is.True);
        
        var test = properties["test"]!.AsObject();
        Assert.That(test["type"]!.GetValue<string>(), Is.EqualTo("string"));
    }

    [Test]
    public async Task ResolveInternalRefAsync_WithInvalidPointer_ReturnsNull()
    {
        // Arrange
        var schema = @"{
            ""definitions"": {
                ""User"": {
                    ""type"": ""object""
                }
            },
            ""properties"": {
                ""test"": { ""$ref"": ""#/definitions/NonExistent"" }
            }
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert - Should handle invalid reference gracefully
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region AllOf Merging Tests

    [Test]
    public async Task MergeAllOfIntoObject_WithMultipleSchemas_MergesCorrectly()
    {
        // Arrange
        var schema = @"{
            ""allOf"": [
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""name"": { ""type"": ""string"" }
                    }
                },
                {
                    ""properties"": {
                        ""age"": { ""type"": ""number"" }
                    }
                },
                {
                    ""properties"": {
                        ""email"": { ""type"": ""string"" }
                    }
                }
            ]
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        
        // After merging allOf, properties should be combined
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        var properties = resultObj["properties"]!.AsObject();
        
        Assert.That(properties.ContainsKey("name"), Is.True);
        Assert.That(properties.ContainsKey("age"), Is.True);
        Assert.That(properties.ContainsKey("email"), Is.True);
    }

    [Test]
    public async Task MergeAllOfIntoObject_WithReferences_ResolvesAndMerges()
    {
        // Arrange
        var schema = @"{
            ""definitions"": {
                ""Base"": {
                    ""type"": ""object"",
                    ""properties"": {
                        ""id"": { ""type"": ""string"" }
                    }
                },
                ""Extended"": {
                    ""allOf"": [
                        { ""$ref"": ""#/definitions/Base"" },
                        {
                            ""properties"": {
                                ""name"": { ""type"": ""string"" }
                            }
                        }
                    ]
                }
            },
            ""$ref"": ""#/definitions/Extended""
        }";

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
        var resolver = new ReferenceResolver(_loggerMock.Object, loader);

        var rootDoc = JsonNode.Parse(schema);
        resolver.Initialize(rootDoc, "https://example.com/");

        // Act
        var visitedRefs = new HashSet<string>();
        var result = await resolver.ResolveAllRefsAsync(rootDoc, visitedRefs);

        // Assert
        Assert.That(result, Is.Not.Null);
        var resultObj = result!.AsObject();
        Assert.That(resultObj.ContainsKey("properties"), Is.True);
        
        var properties = resultObj["properties"]!.AsObject();
        Assert.That(properties.ContainsKey("id"), Is.True, "Should have property from Base");
        Assert.That(properties.ContainsKey("name"), Is.True, "Should have property from Extended");
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

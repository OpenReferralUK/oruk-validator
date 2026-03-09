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

        [Test]
        public async Task ResolveAllRefsAsync_WithInternalDynamicAnchorRef_ResolvesCorrectly()
        {
                // Arrange
                var schema = """
                        {
                            "$dynamicAnchor": "meta",
                            "type": "object",
                            "properties": {
                                "self": {
                                    "$ref": "#meta"
                                }
                            }
                        }
                        """;

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
                resolver.Initialize(rootDoc, "https://example.com/draft/2020-12/schema");

                // Act
                var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                // Assert
                Assert.That(result, Is.Not.Null);
                var resultObj = result!.AsObject();
                Assert.That(resultObj["type"]!.GetValue<string>(), Is.EqualTo("object"));

                var self = resultObj["properties"]!["self"]!.AsObject();
                Assert.That(self["type"]!.GetValue<string>(), Is.EqualTo("object"));
        }

        [Test]
        public async Task ResolveAllRefsAsync_WithExternalAnchorFragment_ResolvesCorrectly()
        {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDirectory);

                try
                {
                        var metaPath = Path.Combine(tempDirectory, "meta.json");
                        await File.WriteAllTextAsync(metaPath, """
                                {
                                    "$dynamicAnchor": "meta",
                                    "type": "object",
                                    "properties": {
                                        "name": {
                                            "type": "string"
                                        }
                                    }
                                }
                                """);

                        var schema = """
                                {
                                    "type": "object",
                                    "properties": {
                                        "meta": {
                                            "$ref": "./meta.json#meta"
                                        }
                                    }
                                }
                                """;

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
                        resolver.Initialize(rootDoc, Path.Combine(tempDirectory, "schema.json"));

                        var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                        Assert.That(result, Is.Not.Null);
                        var meta = result!["properties"]!["meta"]!.AsObject();
                        Assert.That(meta["type"]!.GetValue<string>(), Is.EqualTo("object"));
                        Assert.That(meta["properties"]!["name"]!["type"]!.GetValue<string>(), Is.EqualTo("string"));
                }
                finally
                {
                        if (Directory.Exists(tempDirectory))
                        {
                                Directory.Delete(tempDirectory, recursive: true);
                        }
                }
        }

            [Test]
            public async Task ResolveAllRefsAsync_WithOfficialJsonSchemaMetaRef_FetchesRemotelyAndCaches()
            {
                var schema = """
                    {
                        "type": "object",
                        "properties": {
                            "core": {
                                "$ref": "https://json-schema.org/draft/2020-12/meta/core#meta"
                            }
                        }
                    }
                    """;

                var coreSchemaJson = """
                    {
                        "$id": "https://json-schema.org/draft/2020-12/meta/core",
                        "$dynamicAnchor": "meta",
                        "$defs": {
                            "uriString": {
                                "type": "string"
                            }
                        }
                    }
                    """;

                var requestCount = 0;
                var handler = new MockHttpMessageHandler(_ =>
                {
                    requestCount++;
                    return Task.FromResult(new HttpResponseMessage
                    {
                        StatusCode = System.Net.HttpStatusCode.OK,
                        Content = new StringContent(coreSchemaJson)
                    });
                });

                var cacheOptions = Options.Create(new CacheOptions
                {
                    Enabled = true,
                    ExpirationMinutes = 60,
                    UseSlidingExpiration = true,
                    SlidingExpirationMinutes = 60
                });

                using var httpClient = new HttpClient(handler);
                var loader = new RemoteSchemaLoader(httpClient, _loggerMock.Object, _memoryCache, cacheOptions);

                var firstResolver = new ReferenceResolver(_loggerMock.Object, loader);
                var firstRootDoc = JsonNode.Parse(schema);
                firstResolver.Initialize(firstRootDoc, "https://example.com/root-schema.json");
                var firstResult = await firstResolver.ResolveAllRefsAsync(firstRootDoc, new HashSet<string>());

                var secondResolver = new ReferenceResolver(_loggerMock.Object, loader);
                var secondRootDoc = JsonNode.Parse(schema);
                secondResolver.Initialize(secondRootDoc, "https://example.com/root-schema.json");
                var secondResult = await secondResolver.ResolveAllRefsAsync(secondRootDoc, new HashSet<string>());

                Assert.That(firstResult, Is.Not.Null);
                Assert.That(secondResult, Is.Not.Null);

                var firstCoreSchema = firstResult!["properties"]!["core"]!.AsObject();
                Assert.That(firstCoreSchema["$dynamicAnchor"]!.GetValue<string>(), Is.EqualTo("meta"));
                Assert.That(firstCoreSchema.ContainsKey("$defs"), Is.True);

                var secondCoreSchema = secondResult!["properties"]!["core"]!.AsObject();
                Assert.That(secondCoreSchema["$dynamicAnchor"]!.GetValue<string>(), Is.EqualTo("meta"));

                Assert.That(requestCount, Is.EqualTo(1), "Known schema URL should be fetched once and then served from cache");
            }

        [Test]
        public async Task ResolveAllRefsAsync_WithRelativeLocalFileRef_ResolvesCorrectly()
        {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDirectory);

                try
                {
                        var definitionsPath = Path.Combine(tempDirectory, "definitions.json");
                        await File.WriteAllTextAsync(definitionsPath, """
                                {
                                    "$defs": {
                                        "name": {
                                            "type": "string",
                                            "minLength": 1
                                        }
                                    }
                                }
                                """);

                        var schema = """
                                {
                                    "type": "object",
                                    "properties": {
                                        "name": {
                                            "$ref": "./definitions.json#/$defs/name"
                                        }
                                    }
                                }
                                """;

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
                        var rootSchemaPath = Path.Combine(tempDirectory, "service.json");
                        resolver.Initialize(rootDoc, rootSchemaPath);

                        var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                        Assert.That(result, Is.Not.Null);
                        var properties = result!["properties"]!.AsObject();
                        var nameSchema = properties["name"]!.AsObject();

                        Assert.That(nameSchema["type"]!.GetValue<string>(), Is.EqualTo("string"));
                        Assert.That(nameSchema["minLength"]!.GetValue<int>(), Is.EqualTo(1));
                }
                finally
                {
                        if (Directory.Exists(tempDirectory))
                        {
                                Directory.Delete(tempDirectory, recursive: true);
                        }
                }
        }

            [Test]
            public async Task ResolveAllRefsAsync_WithMissingRelativeLocalFileRef_ReturnsNullAndKeepsParentStable()
            {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDirectory);

                try
                {
                    var schema = """
                        {
                            "type": "object",
                            "properties": {
                            "name": {
                                "$ref": "./missing-definitions.json#/$defs/name"
                            },
                            "status": {
                                "type": "string"
                            }
                            }
                        }
                        """;

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
                    resolver.Initialize(rootDoc, Path.Combine(tempDirectory, "service.json"));

                    var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                    Assert.That(result, Is.Not.Null);
                    var resultObject = result!.AsObject();
                    Assert.That(resultObject["type"]!.GetValue<string>(), Is.EqualTo("object"));

                    var properties = resultObject["properties"]!.AsObject();
                    Assert.That(properties.ContainsKey("name"), Is.True);
                    Assert.That(properties["name"], Is.Null, "Missing local file ref should resolve to null value");

                    var statusSchema = properties["status"]!.AsObject();
                    Assert.That(statusSchema["type"]!.GetValue<string>(), Is.EqualTo("string"), "Sibling schema should be preserved");
                }
                finally
                {
                    if (Directory.Exists(tempDirectory))
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                }
            }

        [Test]
        public async Task ResolveAllRefsAsync_WithFileSchemeRef_ResolvesCorrectly()
        {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDirectory);

                try
                {
                        var definitionsPath = Path.Combine(tempDirectory, "definitions.json");
                        await File.WriteAllTextAsync(definitionsPath, """
                                {
                                    "$defs": {
                                        "id": {
                                            "type": "string",
                                            "pattern": "^[a-z0-9-]+$"
                                        }
                                    }
                                }
                                """);

                        var definitionsUri = new Uri(definitionsPath).AbsoluteUri;
                        var schema = $$"""
                                {
                                    "type": "object",
                                    "properties": {
                                        "id": {
                                            "$ref": "{{definitionsUri}}#/$defs/id"
                                        }
                                    }
                                }
                                """;

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
                        resolver.Initialize(rootDoc, Path.Combine(tempDirectory, "service.json"));

                        var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                        Assert.That(result, Is.Not.Null);
                        var properties = result!["properties"]!.AsObject();
                        var idSchema = properties["id"]!.AsObject();

                        Assert.That(idSchema["type"]!.GetValue<string>(), Is.EqualTo("string"));
                        Assert.That(idSchema["pattern"]!.GetValue<string>(), Is.EqualTo("^[a-z0-9-]+$"));
                }
                finally
                {
                        if (Directory.Exists(tempDirectory))
                        {
                                Directory.Delete(tempDirectory, recursive: true);
                        }
                }
        }

            [Test]
            public async Task ResolveAllRefsAsync_WithNestedRelativeLocalFileRef_ResolvesCorrectly()
            {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                var schemasDirectory = Path.Combine(tempDirectory, "schemas");
                var sharedDirectory = Path.Combine(tempDirectory, "shared");
                Directory.CreateDirectory(schemasDirectory);
                Directory.CreateDirectory(sharedDirectory);

                try
                {
                    var definitionsPath = Path.Combine(sharedDirectory, "definitions.json");
                    await File.WriteAllTextAsync(definitionsPath, """
                        {
                          "$defs": {
                            "title": {
                              "type": "string",
                              "minLength": 3
                            }
                          }
                        }
                        """);

                    var schema = """
                        {
                          "type": "object",
                          "properties": {
                            "title": {
                              "$ref": "../shared/definitions.json#/$defs/title"
                            }
                          }
                        }
                        """;

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
                    var rootSchemaPath = Path.Combine(schemasDirectory, "service.json");
                    resolver.Initialize(rootDoc, rootSchemaPath);

                    var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                    Assert.That(result, Is.Not.Null);
                    var properties = result!["properties"]!.AsObject();
                    var titleSchema = properties["title"]!.AsObject();

                    Assert.That(titleSchema["type"]!.GetValue<string>(), Is.EqualTo("string"));
                    Assert.That(titleSchema["minLength"]!.GetValue<int>(), Is.EqualTo(3));
                }
                finally
                {
                    if (Directory.Exists(tempDirectory))
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                }
            }

            [Test]
            public async Task ResolveAllRefsAsync_WithLocalCrossFileCircularReference_BreaksLoop()
            {
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                var nestedDirectory = Path.Combine(tempDirectory, "nested");
                Directory.CreateDirectory(nestedDirectory);

                try
                {
                    var aPath = Path.Combine(tempDirectory, "A.json");
                    var bPath = Path.Combine(nestedDirectory, "B.json");

                    await File.WriteAllTextAsync(aPath, """
                        {
                          "type": "object",
                          "properties": {
                            "b": {
                              "$ref": "./nested/B.json"
                            }
                          }
                        }
                        """);

                    await File.WriteAllTextAsync(bPath, """
                        {
                          "type": "object",
                          "properties": {
                            "a": {
                              "$ref": "../A.json"
                            }
                          }
                        }
                        """);

                    var schema = """
                        {
                          "type": "object",
                          "properties": {
                            "entry": {
                              "$ref": "./A.json"
                            }
                          }
                        }
                        """;

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
                    var rootSchemaPath = Path.Combine(tempDirectory, "service.json");
                    resolver.Initialize(rootDoc, rootSchemaPath);

                    var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                    Assert.That(result, Is.Not.Null);
                    var entrySchema = result!["properties"]!["entry"]!.AsObject();
                    Assert.That(entrySchema["type"]!.GetValue<string>(), Is.EqualTo("object"));

                    var bSchema = entrySchema["properties"]!["b"]!.AsObject();
                    Assert.That(bSchema["type"]!.GetValue<string>(), Is.EqualTo("object"));

                    var aBackRef = bSchema["properties"]!["a"]!.AsObject();
                    Assert.That(aBackRef.ContainsKey("$ref"), Is.True, "Circular local ref should be preserved as $ref");
                    Assert.That(aBackRef["$ref"]!.GetValue<string>(), Is.EqualTo("../A.json"));
                }
                finally
                {
                    if (Directory.Exists(tempDirectory))
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                }
            }

            [Test]
            public async Task ResolveAllRefsAsync_WithPathNormalizedCircularReference_BreaksLoop()
            {
                // Arrange - A and B reference each other using path-normalized equivalents
                // ./A.json and nested/../A.json both resolve to the same file
                var tempDirectory = Path.Combine(Path.GetTempPath(), $"openreferral-ref-{Guid.NewGuid():N}");
                var nestedDirectory = Path.Combine(tempDirectory, "nested");
                Directory.CreateDirectory(nestedDirectory);

                try
                {
                    var aPath = Path.Combine(tempDirectory, "A.json");
                    var bPath = Path.Combine(tempDirectory, "B.json");

                    // A.json references B.json using ./B.json
                    await File.WriteAllTextAsync(aPath, """
                        {
                          "type": "object",
                          "properties": {
                            "b": {
                              "$ref": "./B.json"
                            }
                          }
                        }
                        """);

                    // B.json references A.json using nested/../A.json (which normalizes to ./A.json)
                    await File.WriteAllTextAsync(bPath, """
                        {
                          "type": "object",
                          "properties": {
                            "a": {
                              "$ref": "nested/../A.json"
                            }
                          }
                        }
                        """);

                    var schema = """
                        {
                          "type": "object",
                          "properties": {
                            "entry": {
                              "$ref": "./A.json"
                            }
                          }
                        }
                        """;

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
                    var rootSchemaPath = Path.Combine(tempDirectory, "service.json");
                    resolver.Initialize(rootDoc, rootSchemaPath);

                    var result = await resolver.ResolveAllRefsAsync(rootDoc, new HashSet<string>());

                    // Assert
                    Assert.That(result, Is.Not.Null);
                    var entrySchema = result!["properties"]!["entry"]!.AsObject();
                    Assert.That(entrySchema["type"]!.GetValue<string>(), Is.EqualTo("object"));

                    // Verify B.json was resolved
                    var bSchema = entrySchema["properties"]!["b"]!.AsObject();
                    Assert.That(bSchema["type"]!.GetValue<string>(), Is.EqualTo("object"));

                    // Verify the circular reference back to A.json is preserved as $ref
                    // The path normalization should detect that nested/../A.json and ./A.json are the same
                    var aBackRef = bSchema["properties"]!["a"]!.AsObject();
                    Assert.That(aBackRef.ContainsKey("$ref"), Is.True, 
                        "Circular local ref should be preserved as $ref even with path-normalized equivalent");
                    Assert.That(aBackRef["$ref"]!.GetValue<string>(), Is.EqualTo("nested/../A.json"));
                }
                finally
                {
                    if (Directory.Exists(tempDirectory))
                    {
                        Directory.Delete(tempDirectory, recursive: true);
                    }
                }
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

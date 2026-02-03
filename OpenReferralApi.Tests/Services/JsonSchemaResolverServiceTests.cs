using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class JsonSchemaResolverServiceTests
{
    private Mock<ILogger<JsonSchemaResolverService>> _loggerMock;
    private Mock<HttpClient> _httpClientMock;
    private JsonSchemaResolverService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<JsonSchemaResolverService>>();
        _httpClientMock = new Mock<HttpClient>();
        _service = new JsonSchemaResolverService(_loggerMock.Object, _httpClientMock.Object);
    }

    #region CreateSchemaFromJsonAsync Tests

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
        Assert.That(result.Type, Is.EqualTo(JSchemaType.Object));
        Assert.That(result.Properties, Has.Count.EqualTo(2));
        Assert.That(result.Properties, Does.ContainKey("name"));
        Assert.That(result.Properties, Does.ContainKey("age"));
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
        Assert.That(result.Type, Is.EqualTo(JSchemaType.Object));
    }

    [Test]
    public async Task CreateSchemaFromJsonAsync_WithOfflineRef_HandlesReference()
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

        // Act
        var result = await _service.CreateSchemaFromJsonAsync(schemaJson);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region CreateSchemaFromUriAsync Tests

    [Test]
    public async Task CreateSchemaFromUriAsync_WithValidUri_FetchesAndCreatesSchema()
    {
        // Arrange
        var schemaUri = "https://example.com/schema.json";
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""name"": { ""type"": ""string"" }
            }
        }";

        var mockHandler = new MockHttpMessageHandler((request) =>
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(schemaJson)
            };
            return Task.FromResult(response);
        });

        var httpClient = new HttpClient(mockHandler);
        var service = new JsonSchemaResolverService(_loggerMock.Object, httpClient);

        // Act
        var result = await service.CreateSchemaFromUriAsync(schemaUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Type, Is.EqualTo(JSchemaType.Object));
    }

    #endregion

    #region ResolveSchemaAsync Tests

    [Test]
    public async Task ResolveSchemaAsync_WithValidSchema_ReturnsSchema()
    {
        // Arrange
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""id"": { ""type"": ""string"" }
            }
        }";
        var schema = JSchema.Parse(schemaJson);

        // Act
        var result = await _service.ResolveSchemaAsync(schema);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.EqualTo(schema));
    }

    #endregion

    #region CreateSchemaWithOpenApiContextAsync Tests

    [Test]
    public async Task CreateSchemaWithOpenApiContextAsync_WithInternalReference_ExpandsReference()
    {
        // Arrange
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""data"": { ""$ref"": ""#/components/schemas/User"" }
            }
        }";

        var openApiDoc = JObject.Parse(@"
        {
            ""openapi"": ""3.0.0"",
            ""components"": {
                ""schemas"": {
                    ""User"": {
                        ""type"": ""object"",
                        ""properties"": {
                            ""id"": { ""type"": ""string"" },
                            ""name"": { ""type"": ""string"" }
                        }
                    }
                }
            }
        }");

        // Act
        var result = await _service.CreateSchemaWithOpenApiContextAsync(schemaJson, openApiDoc, null);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Properties, Is.Not.Empty);
    }

    [Test]
    public async Task CreateSchemaWithOpenApiContextAsync_WithNestedReferences_ExpandsRecursively()
    {
        // Arrange
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""items"": {
                    ""type"": ""array"",
                    ""items"": { ""$ref"": ""#/components/schemas/Item"" }
                }
            }
        }";

        var openApiDoc = JObject.Parse(@"
        {
            ""openapi"": ""3.0.0"",
            ""components"": {
                ""schemas"": {
                    ""Item"": {
                        ""type"": ""object"",
                        ""properties"": {
                            ""id"": { ""type"": ""string"" }
                        }
                    }
                }
            }
        }");

        // Act
        var result = await _service.CreateSchemaWithOpenApiContextAsync(schemaJson, openApiDoc, null);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public async Task CreateSchemaWithOpenApiContextAsync_WithCircularReference_HandlesGracefully()
    {
        // Arrange
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""self"": { ""$ref"": ""#/components/schemas/CircularRef"" }
            }
        }";

        var openApiDoc = JObject.Parse(@"
        {
            ""openapi"": ""3.0.0"",
            ""components"": {
                ""schemas"": {
                    ""CircularRef"": {
                        ""type"": ""object"",
                        ""properties"": {
                            ""self"": { ""$ref"": ""#/components/schemas/CircularRef"" }
                        }
                    }
                }
            }
        }");

        // Act
        var result = await _service.CreateSchemaWithOpenApiContextAsync(schemaJson, openApiDoc, null);

        // Assert - should not throw and should handle the circular reference
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public async Task CreateSchemaWithOpenApiContextAsync_WithDocumentUri_CreatesSchemaWithContext()
    {
        // Arrange
        var schemaJson = @"
        {
            ""type"": ""object"",
            ""properties"": {
                ""data"": { ""$ref"": ""#/components/schemas/User"" }
            }
        }";

        var openApiDoc = JObject.Parse(@"
        {
            ""openapi"": ""3.0.0"",
            ""components"": {
                ""schemas"": {
                    ""User"": {
                        ""type"": ""object"",
                        ""properties"": {
                            ""id"": { ""type"": ""string"" }
                        }
                    }
                }
            }
        }");

        var documentUri = "https://example.com/openapi.json";

        // Act
        var result = await _service.CreateSchemaWithOpenApiContextAsync(schemaJson, openApiDoc, documentUri);

        // Assert
        Assert.That(result, Is.Not.Null);
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


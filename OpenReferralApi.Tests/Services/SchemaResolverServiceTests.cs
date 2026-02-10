using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Services;
using System.Text.Json.Nodes;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class SchemaResolverServiceTests
{
  private Mock<ILogger<SchemaResolverService>> _loggerMock;
  private Mock<HttpClient> _httpClientMock;
  private SchemaResolverService _service;

  [SetUp]
  public void Setup()
  {
    _loggerMock = new Mock<ILogger<SchemaResolverService>>();
    _httpClientMock = new Mock<HttpClient>();
    _service = new SchemaResolverService(_httpClientMock.Object, _loggerMock.Object);
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

  #region Newtonsoft.Json.Schema CreateSchemaFromJsonAsync Tests

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

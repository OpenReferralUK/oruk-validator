using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class JsonValidatorServiceTests
{
    private Mock<ILogger<JsonValidatorService>> _loggerMock;
    private Mock<IPathParsingService> _pathParsingServiceMock;
    private Mock<IRequestProcessingService> _requestProcessingServiceMock;
    private Mock<ISchemaResolverService> _schemaResolverServiceMock;
    private HttpClient _httpClient;
    private JsonValidatorService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<JsonValidatorService>>();
        _pathParsingServiceMock = new Mock<IPathParsingService>();
        _requestProcessingServiceMock = new Mock<IRequestProcessingService>();
        _schemaResolverServiceMock = new Mock<ISchemaResolverService>();

        _requestProcessingServiceMock
            .Setup(service => service.ExecuteWithConcurrencyControlAsync(
                It.IsAny<Func<CancellationToken, Task<ValidationResult>>>(),
                It.IsAny<ValidationOptions?>(),
                It.IsAny<CancellationToken>()))
            .Returns((Func<CancellationToken, Task<ValidationResult>> func, ValidationOptions? options, CancellationToken ct) => func(ct));

        _requestProcessingServiceMock
            .Setup(service => service.ExecuteWithRetryAsync(
                It.IsAny<Func<CancellationToken, Task<JSchema>>>(),
                It.IsAny<ValidationOptions?>(),
                It.IsAny<CancellationToken>()))
            .Returns((Func<CancellationToken, Task<JSchema>> func, ValidationOptions? options, CancellationToken ct) => func(ct));

        _requestProcessingServiceMock
            .Setup(service => service.ExecuteWithRetryAsync(
                It.IsAny<Func<CancellationToken, Task<object>>>(),
                It.IsAny<ValidationOptions?>(),
                It.IsAny<CancellationToken>()))
            .Returns((Func<CancellationToken, Task<object>> func, ValidationOptions? options, CancellationToken ct) => func(ct));

        _requestProcessingServiceMock
            .Setup(service => service.CreateTimeoutToken(It.IsAny<ValidationOptions?>(), It.IsAny<CancellationToken>()))
            .Returns((ValidationOptions? options, CancellationToken ct) => CancellationTokenSource.CreateLinkedTokenSource(ct));

        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DataSourceAuthentication>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, string documentUri, DataSourceAuthentication auth, CancellationToken ct) => JSchema.Parse(schemaJson));

        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, CancellationToken ct) => JSchema.Parse(schemaJson));

        var mockHandler = new MockHttpMessageHandler("{}", "{}");
        _httpClient = new HttpClient(mockHandler);

        _service = new JsonValidatorService(
            _loggerMock.Object,
            _httpClient,
            _pathParsingServiceMock.Object,
            _requestProcessingServiceMock.Object,
            _schemaResolverServiceMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _httpClient?.Dispose();
    }

    [Test]
    public async Task ValidateAsync_WithDirectJsonAndSchema_ReturnsValidResult()
    {
        // Arrange
        var schema = new
        {
            title = "Person",
            description = "A person record",
            type = "object",
            properties = new { name = new { type = "string" } },
            required = new[] { "name" }
        };

        var request = new ValidationRequest
        {
            JsonData = new { name = "Ada" },
            Schema = schema
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.Metadata, Is.Not.Null);
        Assert.That(result.Metadata!.SchemaTitle, Is.EqualTo("Person"));
        Assert.That(result.Metadata.DataSource, Is.EqualTo("direct"));
    }

    [Test]
    public async Task ValidateAsync_WithInvalidData_ReturnsValidationErrors()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new { name = new { type = "string" } },
            required = new[] { "name" }
        };

        var request = new ValidationRequest
        {
            JsonData = new { },
            Schema = schema
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(e => e.ErrorCode == "VALIDATION_ERROR"));
    }

    [Test]
    public async Task ValidateAsync_WithDataUrl_FetchesAndValidates()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new { name = new { type = "string" } },
            required = new[] { "name" }
        };

        var dataUrl = "https://example.com/data.json";
        _pathParsingServiceMock
            .Setup(service => service.ValidateAndParseDataUrlAsync(dataUrl, It.IsAny<ValidationOptions?>()))
            .ReturnsAsync(new Uri(dataUrl));

        SetupHttpMock("{}", "{\"name\":\"Ada\"}");

        var request = new ValidationRequest
        {
            DataUrl = dataUrl,
            Schema = schema
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.Metadata, Is.Not.Null);
        Assert.That(result.Metadata!.DataSource, Is.EqualTo(dataUrl));
    }

    [Test]
    public async Task ValidateWithSchemaUriAsync_LoadsSchemaAndValidates()
    {
        // Arrange
        var schemaUri = "https://example.com/schema.json";
        _pathParsingServiceMock
            .Setup(service => service.ValidateAndParseSchemaUriAsync(schemaUri, It.IsAny<ValidationOptions?>()))
            .ReturnsAsync(new Uri(schemaUri));

        var schemaJson = @"{""type"":""object"",""properties"":{ ""name"": {""type"":""string""}},""required"": [""name""] }";
        SetupHttpMock(schemaJson, "{\"name\":\"Ada\"}");

        // Act
        var result = await _service.ValidateWithSchemaUriAsync(new { name = "Ada" }, schemaUri);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public async Task ValidateSchemaAsync_WithMissingType_ReturnsWarning()
    {
        // Arrange
        var schema = new { title = "Schema" };

        // Act
        var result = await _service.ValidateSchemaAsync(schema);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Exactly(1).Matches<OpenReferralApi.Core.Models.ValidationError>(error => error.ErrorCode == "MISSING_TYPE"));
    }

    [Test]
    public async Task IsValidAsync_WithValidRequest_ReturnsTrue()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new { name = new { type = "string" } },
            required = new[] { "name" }
        };

        var request = new ValidationRequest
        {
            JsonData = new { name = "Ada" },
            Schema = schema
        };

        // Act
        var result = await _service.IsValidAsync(request);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ValidateAsync_WithMissingJsonDataAndUrl_ThrowsArgumentException()
    {
        // Arrange
        var request = new ValidationRequest
        {
            Schema = new { type = "object" }
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(async () =>
            await _service.ValidateAsync(request));
    }

    [Test]
    public void ValidateAsync_WithMissingSchema_ThrowsArgumentException()
    {
        // Arrange
        var request = new ValidationRequest
        {
            JsonData = new { name = "Ada" }
        };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(async () =>
            await _service.ValidateAsync(request));
    }

    [Test]
    public void ValidateWithSchemaUriAsync_WhenSchemaLoadFails_ThrowsInvalidOperation()
    {
        // Arrange
        var schemaUri = "https://example.com/schema.json";
        _pathParsingServiceMock
            .Setup(service => service.ValidateAndParseSchemaUriAsync(schemaUri, It.IsAny<ValidationOptions?>()))
            .ThrowsAsync(new ArgumentException("Invalid schema URI"));

        // Act & Assert
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.ValidateWithSchemaUriAsync(new { name = "Ada" }, schemaUri));
    }

    [Test]
    public async Task ValidateSchemaAsync_WhenSchemaResolverThrows_ReturnsError()
    {
        // Arrange
        _schemaResolverServiceMock
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Schema parse failed"));

        // Act
        var result = await _service.ValidateSchemaAsync(new { type = "object" });

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Exactly(1).Matches<OpenReferralApi.Core.Models.ValidationError>(error => error.ErrorCode == "SCHEMA_VALIDATION_ERROR"));
    }

    [Test]
    public async Task ValidateAsync_WithReportAdditionalFields_ReportsFieldsNotInSchema()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new
            {
                name = new { type = "string" },
                age = new { type = "number" }
            },
            required = new[] { "name" },
            additionalProperties = true
        };

        var request = new ValidationRequest
        {
            JsonData = new
            {
                name = "Ada Lovelace",
                age = 36,
                email = "ada@example.com",  // Not in schema
                address = new  // Not in schema
                {
                    city = "London",
                    country = "UK"
                }
            },
            Schema = schema,
            Options = new ValidationOptions
            {
                ReportAdditionalFields = true
            }
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True, "Data should be valid even with additional fields");
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD" && e.Path == "email"),
            "Should report 'email' as an additional field");
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD" && e.Path == "address"),
            "Should report 'address' as an additional field");
        Assert.That(result.Errors.Where(e => e.ErrorCode == "ADDITIONAL_FIELD").All(e => e.Severity == "Info"),
            "Additional field warnings should have 'Info' severity");
    }

    [Test]
    public async Task ValidateAsync_WithReportAdditionalFieldsFalse_DoesNotReportAdditionalFields()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new
            {
                name = new { type = "string" }
            },
            required = new[] { "name" },
            additionalProperties = true
        };

        var request = new ValidationRequest
        {
            JsonData = new
            {
                name = "Ada Lovelace",
                email = "ada@example.com"  // Not in schema
            },
            Schema = schema,
            Options = new ValidationOptions
            {
                ReportAdditionalFields = false  // Explicitly disabled
            }
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Has.None.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD"),
            "Should not report additional fields when option is disabled");
    }

    [Test]
    public async Task ValidateAsync_WithReportAdditionalFields_HandlesNestedObjects()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new
            {
                name = new { type = "string" },
                address = new
                {
                    type = "object",
                    properties = new
                    {
                        city = new { type = "string" }
                    },
                    additionalProperties = true
                }
            },
            additionalProperties = true
        };

        var request = new ValidationRequest
        {
            JsonData = new
            {
                name = "Ada Lovelace",
                address = new
                {
                    city = "London",
                    postcode = "SW1A 1AA"  // Not in schema
                }
            },
            Schema = schema,
            Options = new ValidationOptions
            {
                ReportAdditionalFields = true
            }
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD" && e.Path == "address.postcode"),
            "Should report nested additional fields");
    }

    [Test]
    public async Task ValidateAsync_WithReportAdditionalFields_HandlesArrays()
    {
        // Arrange
        var schema = new
        {
            type = "object",
            properties = new
            {
                users = new
                {
                    type = "array",
                    items = new
                    {
                        type = "object",
                        properties = new
                        {
                            name = new { type = "string" }
                        },
                        additionalProperties = true
                    }
                }
            },
            additionalProperties = true
        };

        var request = new ValidationRequest
        {
            JsonData = new
            {
                users = new object[]
                {
                    new { name = "Ada", age = 36 },  // 'age' not in schema
                    new { name = "Charles", role = "Professor" }  // 'role' not in schema
                }
            },
            Schema = schema,
            Options = new ValidationOptions
            {
                ReportAdditionalFields = true
            }
        };

        // Act
        var result = await _service.ValidateAsync(request);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD" && e.Path == "users[0].age"),
            "Should report additional fields in array items");
        Assert.That(result.Errors, Has.Some.Matches<OpenReferralApi.Core.Models.ValidationError>(
            e => e.ErrorCode == "ADDITIONAL_FIELD" && e.Path == "users[1].role"),
            "Should report additional fields in array items");
    }

    private void SetupHttpMock(string schemaJson, string dataJson)
    {
        var mockHandler = new MockHttpMessageHandler(schemaJson, dataJson);
        _httpClient?.Dispose();
        _httpClient = new HttpClient(mockHandler);
        _service = new JsonValidatorService(
            _loggerMock.Object,
            _httpClient,
            _pathParsingServiceMock.Object,
            _requestProcessingServiceMock.Object,
            _schemaResolverServiceMock.Object);
    }

    private sealed class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _schemaJson;
        private readonly string _dataJson;

        public MockHttpMessageHandler(string schemaJson, string dataJson)
        {
            _schemaJson = schemaJson;
            _dataJson = dataJson;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri?.ToString() ?? string.Empty;
            var responseBody = requestUri.Contains("schema", StringComparison.OrdinalIgnoreCase)
                ? _schemaJson
                : _dataJson;

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody)
            });
        }
    }
}

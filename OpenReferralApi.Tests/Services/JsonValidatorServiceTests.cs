using FluentAssertions;
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
    private Mock<IJsonSchemaResolverService> _schemaResolverServiceMock;
    private HttpClient _httpClient;
    private JsonValidatorService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<JsonValidatorService>>();
        _pathParsingServiceMock = new Mock<IPathParsingService>();
        _requestProcessingServiceMock = new Mock<IRequestProcessingService>();
        _schemaResolverServiceMock = new Mock<IJsonSchemaResolverService>();

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
            .Setup(service => service.CreateSchemaFromJsonAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string schemaJson, string documentUri, CancellationToken ct) => JSchema.Parse(schemaJson));

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
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.Metadata.Should().NotBeNull();
        result.Metadata!.SchemaTitle.Should().Be("Person");
        result.Metadata.DataSource.Should().Be("direct");
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
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().Contain(e => e.ErrorCode == "VALIDATION_ERROR");
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
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.Metadata.Should().NotBeNull();
        result.Metadata!.DataSource.Should().Be(dataUrl);
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
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Test]
    public async Task ValidateSchemaAsync_WithMissingType_ReturnsWarning()
    {
        // Arrange
        var schema = new { title = "Schema" };

        // Act
        var result = await _service.ValidateSchemaAsync(schema);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(error => error.ErrorCode == "MISSING_TYPE");
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
        result.Should().BeTrue();
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
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle(error => error.ErrorCode == "SCHEMA_VALIDATION_ERROR");
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

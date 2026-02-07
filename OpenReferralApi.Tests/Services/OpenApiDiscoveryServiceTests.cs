using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Net;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OpenApiDiscoveryServiceTests
{
    private Mock<IHttpClientFactory> _httpClientFactoryMock;
    private Mock<ILogger<OpenApiDiscoveryService>> _loggerMock;
    private Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private Mock<IOptions<SpecificationOptions>> _specificationOptionsMock;
    private HttpClient _httpClient;
    private OpenApiDiscoveryService _service;

    [SetUp]
    public void Setup()
    {
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _loggerMock = new Mock<ILogger<OpenApiDiscoveryService>>();
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        _specificationOptionsMock = new Mock<IOptions<SpecificationOptions>>();
        _httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        
        _httpClientFactoryMock
            .Setup(f => f.CreateClient("OpenApiValidationService"))
            .Returns(_httpClient);

        _specificationOptionsMock
            .Setup(o => o.Value)
            .Returns(new SpecificationOptions
            {
                BaseUrl = "https://raw.githubusercontent.com/tpximpact/OpenReferralApi/refs/heads/staging/OpenReferralApi/Schemas/"
            });

        _service = new OpenApiDiscoveryService(_httpClientFactoryMock.Object, _loggerMock.Object, _specificationOptionsMock.Object);
    }

    [TearDown]
    public void TearDown()
    {
        _httpClient?.Dispose();
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithNullBaseUrl_ReturnsNull()
    {
        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(null!);

        // Assert
        Assert.That(url, Is.Null);
        Assert.That(reason, Is.Null);
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithEmptyBaseUrl_ReturnsNull()
    {
        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync("");

        // Assert
        Assert.That(url, Is.Null);
        Assert.That(reason, Is.Null);
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithExplicitOpenApiUrl_ReturnsDiscoveredUrl()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var openApiUrl = "https://api.example.com/openapi.json";
        var responseContent = $@"{{""openapi_url"": ""{openApiUrl}""}}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Is.EqualTo(openApiUrl));
        Assert.That(reason, Does.Contain("openapi_url field"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithOpenapiUrlCamelCase_ReturnsDiscoveredUrl()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var openApiUrl = "https://api.example.com/api-docs";
        var responseContent = $@"{{""openapiUrl"": ""{openApiUrl}""}}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Is.EqualTo(openApiUrl));
        Assert.That(reason, Does.Contain("openapi_url field"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithOpenApiUrlUnderscoreCamelCase_ReturnsDiscoveredUrl()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var openApiUrl = "https://api.example.com/swagger.json";
        var responseContent = $@"{{""open_api_url"": ""{openApiUrl}""}}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Is.EqualTo(openApiUrl));
        Assert.That(reason, Does.Contain("openapi_url field"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithVersion1_0_ReturnsVersion1_0Spec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""1.0""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Standard version 1.0"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithVersion3_0_ReturnsVersion3_0Spec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""3.0""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("3.0/openapi.json"));
        Assert.That(reason, Does.Contain("Standard version 3.0"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithVersionHSDSUK3_0_ReturnsVersion3_0Spec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""HSDS-UK-3.0""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("3.0/openapi.json"));
        Assert.That(reason, Does.Contain("Standard version HSDS-UK-3.0"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithVersionV3_1_ReturnsVersion3_1Spec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""V3.1""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("3.1/openapi.json"));
        Assert.That(reason, Does.Contain("Standard version V3.1"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithNoVersionOrOpenApiUrl_ReturnsDefaultSpec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""name"": ""Test API""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Defaulted to HSDS-UK 1.0"));
        Assert.That(reason, Does.Contain("no version or openapi_url found"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithHttpError_ReturnsDefaultSpec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";

        SetupHttpResponse(HttpStatusCode.NotFound, "Not Found");

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Defaulted to HSDS-UK 1.0"));
        Assert.That(reason, Does.Contain("base URL request failed"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithInvalidJson_ReturnsDefaultSpec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = "This is not valid JSON";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Defaulted to HSDS-UK 1.0"));
        Assert.That(reason, Does.Contain("failed to parse"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithHttpException_ReturnsDefaultSpec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Connection failed"));

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Defaulted to HSDS-UK 1.0"));
        Assert.That(reason, Does.Contain("error requesting base URL"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithInvalidVersionFormat_ReturnsDefaultSpec()
    {
        // Arrange
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""invalid-version-string""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("1.0/openapi.json"));
        Assert.That(reason, Does.Contain("Defaulted to HSDS-UK 1.0"));
    }

    [Test]
    public async Task DiscoverOpenApiUrlAsync_WithBothVersionAndOpenApiUrl_UsesVersion()
    {
        // Arrange - The service checks version first, then falls back to openapi_url
        var baseUrl = "https://api.example.com";
        var responseContent = @"{""version"": ""3.0"", ""openapi_url"": ""https://api.example.com/custom.json""}";

        SetupHttpResponse(HttpStatusCode.OK, responseContent);

        // Act
        var (url, reason) = await _service.DiscoverOpenApiUrlAsync(baseUrl);

        // Assert
        Assert.That(url, Does.Contain("3.0/openapi.json"));
        Assert.That(reason, Does.Contain("Standard version 3.0"));
    }

    private void SetupHttpResponse(HttpStatusCode statusCode, string content)
    {
        var mockResponse = new HttpResponseMessage
        {
            StatusCode = statusCode,
            Content = new StringContent(content)
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(mockResponse);
    }
}

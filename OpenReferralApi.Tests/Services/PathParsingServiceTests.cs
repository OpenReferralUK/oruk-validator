using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using System.Net;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class PathParsingServiceTests
{
    private Mock<ILogger<PathParsingService>> _loggerMock;
    private Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private HttpClient _httpClient;
    private PathParsingService _service;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<PathParsingService>>();
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        _httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        _service = new PathParsingService(_loggerMock.Object, _httpClient);
    }

    [TearDown]
    public void TearDown()
    {
        _httpClient?.Dispose();
    }

    #region ValidateAndParseUriAsync Tests

    [Test]
    public async Task ValidateAndParseUriAsync_WithValidHttpUrl_ReturnsUri()
    {
        // Arrange
        var validUrl = "https://example.com/api/data";

        // Act
        var result = await _service.ValidateAndParseUriAsync(validUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AbsoluteUri, Is.EqualTo(validUrl));
        Assert.That(result.Scheme, Is.EqualTo("https"));
    }

    [Test]
    public void ValidateAndParseUriAsync_WithNullUrl_ThrowsArgumentException()
    {
        // Act & Assert
        var act = async () => await _service.ValidateAndParseUriAsync(null!);
        var ex = Assert.ThrowsAsync<ArgumentException>(async () => await act());
        Assert.That(ex!.Message, Does.Contain("cannot be null or empty"));
    }

    [Test]
    public void ValidateAndParseUriAsync_WithEmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        var act = async () => await _service.ValidateAndParseUriAsync("");
        Assert.ThrowsAsync<ArgumentException>(async () => await act());
    }

    [Test]
    public void ValidateAndParseUriAsync_WithInvalidScheme_ThrowsArgumentException()
    {
        // Act & Assert
        var act = async () => await _service.ValidateAndParseUriAsync("ssh://example.com");
        var ex = Assert.ThrowsAsync<ArgumentException>(async () => await act());
        Assert.That(ex!.Message, Does.Contain("not supported"));
    }

    [Test]
    public void ValidateAndParseUriAsync_WithMalformedUrl_ThrowsArgumentException()
    {
        // Act & Assert
        var act = async () => await _service.ValidateAndParseUriAsync("not a valid url");
        var ex = Assert.ThrowsAsync<ArgumentException>(async () => await act());
        Assert.That(ex!.Message, Does.Contain("Invalid"));
    }

    #endregion

    #region ValidateAndParseDataUrlAsync Tests

    [Test]
    public async Task ValidateAndParseDataUrlAsync_WithValidHttpsUrl_ReturnsUri()
    {
        // Arrange
        var validUrl = "https://api.example.com/data.json";

        // Act
        var result = await _service.ValidateAndParseDataUrlAsync(validUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Scheme, Is.EqualTo("https"));
    }

    [Test]
    public void ValidateAndParseDataUrlAsync_WithFtpScheme_ThrowsArgumentException()
    {
        // Arrange - FTP not allowed for data URLs (only http/https)
        var ftpUrl = "ftp://ftp.example.com/data.json";

        // Act & Assert
        var act = async () => await _service.ValidateAndParseDataUrlAsync(ftpUrl);
        var ex = Assert.ThrowsAsync<ArgumentException>(async () => await act());
        Assert.That(ex!.Message, Does.Contain("not supported"));
    }

    #endregion

    #region ValidateAndParseSchemaUriAsync Tests

    [Test]
    public async Task ValidateAndParseSchemaUriAsync_WithHttpsUrl_ReturnsUri()
    {
        // Arrange
        var schemaUrl = "https://schemas.example.com/v1/schema.json";

        // Act
        var result = await _service.ValidateAndParseSchemaUriAsync(schemaUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Scheme, Is.EqualTo("https"));
    }

    [Test]
    public async Task ValidateAndParseSchemaUriAsync_WithFileUrl_ReturnsUri()
    {
        // Arrange
        var fileUrl = "file:///path/to/schema.json";

        // Act
        var result = await _service.ValidateAndParseSchemaUriAsync(fileUrl);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Scheme, Is.EqualTo("file"));
    }

    #endregion

    #region CheckUriAccessibilityAsync Tests

    [Test]
    public async Task CheckUriAccessibilityAsync_WithAccessibleHttpUrl_ReturnsAccessibleResult()
    {
        // Arrange
        var uri = new Uri("https://example.com/api");
        var mockResponse = new HttpResponseMessage
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StringContent("test content")
        };
        mockResponse.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        mockResponse.Content.Headers.ContentLength = 12;

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(r => r.Method == HttpMethod.Head),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(mockResponse);

        // Act
        var result = await _service.CheckUriAccessibilityAsync(uri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsAccessible, Is.True);
        Assert.That(result.StatusCode, Is.EqualTo(200));
        Assert.That(result.ContentType, Is.EqualTo("application/json"));
        Assert.That(result.ContentLength, Is.EqualTo(12));
    }

    [Test]
    public async Task CheckUriAccessibilityAsync_WithNotFoundUrl_ReturnsInaccessibleResult()
    {
        // Arrange
        var uri = new Uri("https://example.com/notfound");
        var mockResponse = new HttpResponseMessage
        {
            StatusCode = HttpStatusCode.NotFound,
            ReasonPhrase = "Not Found"
        };

        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(mockResponse);

        // Act
        var result = await _service.CheckUriAccessibilityAsync(uri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsAccessible, Is.False);
        Assert.That(result.StatusCode, Is.EqualTo(404));
        Assert.That(result.ErrorMessage, Does.Contain("NotFound"));
    }

    [Test]
    public async Task CheckUriAccessibilityAsync_WithFileUri_ChecksFileExistence()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        File.WriteAllText(tempFile, "test content");
        var fileUri = new Uri($"file://{tempFile}");

        try
        {
            // Act
            var result = await _service.CheckUriAccessibilityAsync(fileUri);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.IsAccessible, Is.True);
            Assert.That(result.StatusCode, Is.EqualTo(200));
            Assert.That(result.ContentLength, Is.GreaterThan(0));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Test]
    public async Task CheckUriAccessibilityAsync_WithNonExistentFile_ReturnsNotAccessible()
    {
        // Arrange
        var fileUri = new Uri("file:///nonexistent/path/file.json");

        // Act
        var result = await _service.CheckUriAccessibilityAsync(fileUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsAccessible, Is.False);
        Assert.That(result.StatusCode, Is.EqualTo(404));
        Assert.That(result.ErrorMessage, Does.Contain("not found"));
    }

    [Test]
    public async Task CheckUriAccessibilityAsync_WithUnsupportedScheme_ReturnsUnsupportedResult()
    {
        // Arrange
        var ftpUri = new Uri("ftp://ftp.example.com/file.json");

        // Act
        var result = await _service.CheckUriAccessibilityAsync(ftpUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsAccessible, Is.False);
        Assert.That(result.ErrorMessage, Does.Contain("Unsupported scheme"));
    }

    [Test]
    public async Task CheckUriAccessibilityAsync_WithTimeout_ReturnsTimeoutResult()
    {
        // Arrange
        var uri = new Uri("https://example.com/slow");
        _httpMessageHandlerMock
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new TaskCanceledException("Request timeout", new TimeoutException()));

        var options = new ValidationOptions { TimeoutSeconds = 1 };

        // Act
        var result = await _service.CheckUriAccessibilityAsync(uri, options);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsAccessible, Is.False);
    }

    #endregion

    #region ResolveRelativeUri Tests

    [Test]
    public void ResolveRelativeUri_WithRelativePath_ReturnsAbsoluteUri()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/api/v1/");
        var relativeUri = "schemas/schema.json";

        // Act
        var result = _service.ResolveRelativeUri(baseUri, relativeUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AbsoluteUri, Is.EqualTo("https://example.com/api/v1/schemas/schema.json"));
    }

    [Test]
    public void ResolveRelativeUri_WithAbsoluteUrl_ReturnsAbsoluteUri()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/api/");
        var absoluteUri = "https://other.com/schema.json";

        // Act
        var result = _service.ResolveRelativeUri(baseUri, absoluteUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AbsoluteUri, Is.EqualTo(absoluteUri));
    }

    [Test]
    public void ResolveRelativeUri_WithParentPath_ReturnsCorrectUri()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/api/v1/");
        var relativeUri = "../schemas/schema.json";

        // Act
        var result = _service.ResolveRelativeUri(baseUri, relativeUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AbsoluteUri, Is.EqualTo("https://example.com/api/schemas/schema.json"));
    }

    [Test]
    public void ResolveRelativeUri_WithNullBase_ThrowsArgumentException()
    {
        // Arrange
        var relativeUri = "schemas/schema.json";

        // Act & Assert
        TestDelegate act = () => _service.ResolveRelativeUri(null!, relativeUri);
        Assert.Throws<ArgumentException>(act);
    }

    [Test]
    public void ResolveRelativeUri_WithEmptyRelativeUri_ThrowsArgumentException()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/api/");

        // Act & Assert
        TestDelegate act = () => _service.ResolveRelativeUri(baseUri, "");
        var ex = Assert.Throws<ArgumentException>(act);
        Assert.That(ex!.Message, Does.Contain("cannot be null or empty"));
    }

    [Test]
    public void ResolveRelativeUri_WithRootRelativePath_ReturnsCorrectUri()
    {
        // Arrange
        var baseUri = new Uri("https://example.com/api/v1/");
        var relativeUri = "/schemas/schema.json";

        // Act
        var result = _service.ResolveRelativeUri(baseUri, relativeUri);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.AbsoluteUri, Is.EqualTo("https://example.com/schemas/schema.json"));
    }

    #endregion

    #region Security Validation Tests

    [Test]
    public void ValidateAndParseUriAsync_WithDisallowedPort_ThrowsArgumentException()
    {
        // Arrange - port 22 (SSH) should be disallowed
        var urlWithDisallowedPort = "https://example.com:22/api";

        // Act & Assert
        var act = async () => await _service.ValidateAndParseUriAsync(urlWithDisallowedPort);
        var ex = Assert.ThrowsAsync<ArgumentException>(async () => await act());
        Assert.That(ex!.Message, Does.Contain("disallowed port"));
    }

    [Test]
    public async Task ValidateAndParseUriAsync_WithAllowedPort_ReturnsUri()
    {
        // Arrange
        var urlWithAllowedPort = "https://example.com:8443/api";

        // Act
        var result = await _service.ValidateAndParseUriAsync(urlWithAllowedPort);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Port, Is.EqualTo(8443));
    }

    [Test]
    public async Task ValidateAndParseUriAsync_WithStandardPort_ReturnsUri()
    {
        // Arrange
        var url = "https://example.com/api"; // Standard port 443

        // Act
        var result = await _service.ValidateAndParseUriAsync(url);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Port, Is.EqualTo(443));
    }

    #endregion
}

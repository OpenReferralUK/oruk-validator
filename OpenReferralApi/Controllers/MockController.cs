using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OutputCaching;

namespace OpenReferralApi.Controllers;

[ApiController]
[Route("api/[Controller]")]
// This hides the entire controller from Swagger UI
[ApiExplorerSettings(IgnoreApi = true)]
public class MockController : ControllerBase
{
    private const string MockPath = "Mocks/V3.0-UK-";
    private readonly ILogger<MockController> _logger;

    public MockController(ILogger<MockController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Resolves the appropriate mock file path based on the request path (fail/warn/default)
    /// </summary>
    private string ResolveMockPath(string fileName)
    {
        var requestPath = Request.Path.ToString();
        if (requestPath.Contains("fail", StringComparison.CurrentCultureIgnoreCase))
            return $"{MockPath}Fail/{fileName}";
        if (requestPath.Contains("warn", StringComparison.CurrentCultureIgnoreCase))
            return $"{MockPath}Warn/{fileName}";
        return $"{MockPath}Default/{fileName}";
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 API details GET / endpoint  
    /// </summary>
    [HttpGet]
    [Route("")]
    [Route("fail")]
    [Route("warn")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetServiceMetadata()
    {
        return await ReadJsonFile(ResolveMockPath("api_details.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /services endpoint  
    /// </summary>
    [HttpGet]
    [Route("services")]
    [Route("fail/services")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [Route("warn/services")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetServices()
    {
        return await ReadJsonFile(ResolveMockPath("service_list.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /services/{id} endpoint.
    /// As this is a mock the {id} value does not need to be valid 
    /// </summary>
    [HttpGet]
    [Route("services/{id}")]
    [Route("fail/services/{id}")]
    [Route("warn/services/{id}")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetServicesById()
    {
        return await ReadJsonFile(ResolveMockPath("service_full.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /taxonomies endpoint  
    /// </summary>
    [HttpGet]
    [Route("taxonomies")]
    [Route("fail/taxonomies")]
    [Route("warn/taxonomies")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetTaxonomies()
    {
        return await ReadJsonFile(ResolveMockPath("taxonomy_list.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /taxonomies/{id} endpoint. 
    /// As this is a mock the {id} value does not need to be valid
    /// </summary>
    [HttpGet]
    [Route("taxonomies/{id}")]
    [Route("fail/taxonomies/{id}")]
    [Route("warn/taxonomies/{id}")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetTaxonomiesById()
    {
        return await ReadJsonFile(ResolveMockPath("taxonomy.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /taxonomy_terms endpoint
    /// </summary>
    [HttpGet]
    [Route("taxonomy_terms")]
    [Route("fail/taxonomy_terms")]
    [Route("warn/taxonomy_terms")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetTaxonomyTerms()
    {
        return await ReadJsonFile(ResolveMockPath("taxonomy_term_list.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /taxonomy_terms/{id} endpoint.  
    /// As this is a mock the {id} value does not need to be valid
    /// </summary>
    [HttpGet]
    [Route("taxonomy_terms/{id}")]
    [Route("fail/taxonomy_terms/{id}")]
    [Route("warn/taxonomy_terms/{id}")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetTaxonomyTermsById()
    {
        return await ReadJsonFile(ResolveMockPath("taxonomy_term.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /service_at_locations endpoint
    /// </summary>
    [HttpGet]
    [Route("service_at_locations")]
    [Route("fail/service_at_locations")]
    [Route("warn/service_at_locations")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetServiceAtLocations()
    {
        return await ReadJsonFile(ResolveMockPath("service_at_location_list.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the expected response from the V3 GET /service_at_locations/{id} endpoint.  
    /// As this is a mock the {id} value does not need to be valid
    /// </summary>
    [HttpGet]
    [Route("service_at_locations/{id}")]
    [Route("fail/service_at_locations/{id}")]
    [Route("warn/service_at_locations/{id}")]
    [OutputCache(PolicyName = "MockEndpoints")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetServiceAtLocationsById()
    {
        return await ReadJsonFile(ResolveMockPath("service_at_location_full.json"));
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the V1 `/validate` response 
    /// </summary>
    /// <param name="serviceUrl"></param>
    [HttpPost]
    [Route("v1/validate")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetV1ValidatorMock([FromQuery]string? serviceUrl = null)
    {
        return await ReadJsonFile("Mocks/V1.0-UK-Default/V1_ValidateResponse.json");
    }
    
    /// <summary>
    /// A MOCK endpoint that returns an example of the V1 `/dashboard` response
    /// </summary>
    [HttpGet]
    [Route("v1/dashboard")]
    [Route("dashboard")]
    [ProducesResponseType(typeof(JsonNode), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetDashboardMock()
    {
        return await ReadJsonFile("Mocks/V1.0-UK-Default/V1_DashboardResponse.json");
    }

    private async Task<IActionResult> ReadJsonFile(string filePath)
    {
        try
        {
            _logger.LogDebug("Reading mock JSON file: {FilePath}", filePath);
            
            // Open the text file using a stream reader.
            using StreamReader reader = new(filePath);

            // Read the stream as a string.
            var mock = await reader.ReadToEndAsync();

            var mockResponse = JsonNode.Parse(mock);

            return Ok(mockResponse);
        }
        catch (FileNotFoundException ex)
        {
            _logger.LogError(ex, "Mock file not found: {FilePath}", filePath);
            return NotFound(new { error = "Mock file not found", file = filePath });
        }
        catch (IOException ex)
        {
            _logger.LogError(ex, "Error reading mock file: {FilePath}", filePath);
            return StatusCode(500, new { error = "Error reading mock file", message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error reading mock file: {FilePath}", filePath);
            return StatusCode(500, new { error = "An unexpected error occurred", message = ex.Message });
        }
    } 
}
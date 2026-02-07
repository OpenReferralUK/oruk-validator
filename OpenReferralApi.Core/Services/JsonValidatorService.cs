using System;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Models;
using ValidationError = OpenReferralApi.Core.Models.ValidationError;

namespace OpenReferralApi.Core.Services;

public interface IJsonValidatorService
{
    Task<ValidationResult> ValidateAsync(ValidationRequest request, CancellationToken cancellationToken = default);
    Task<ValidationResult> ValidateWithSchemaUriAsync(object jsonData, string schemaUri, ValidationOptions? options = null, CancellationToken cancellationToken = default);
    Task<bool> IsValidAsync(ValidationRequest request, CancellationToken cancellationToken = default);
    Task<ValidationResult> ValidateSchemaAsync(object schema, CancellationToken cancellationToken = default);
}

public class JsonValidatorService : IJsonValidatorService
{
    private readonly ILogger<JsonValidatorService> _logger;
    private readonly HttpClient _httpClient;
    private readonly IPathParsingService _pathParsingService;
    private readonly IRequestProcessingService _requestProcessingService;
    private readonly IJsonSchemaResolverService _schemaResolverService;

    public JsonValidatorService(
        ILogger<JsonValidatorService> logger,
        HttpClient httpClient,
        IPathParsingService pathParsingService,
        IRequestProcessingService requestProcessingService,
        IJsonSchemaResolverService schemaResolverService)
    {
        _logger = logger;
        _httpClient = httpClient;
        _pathParsingService = pathParsingService;
        _requestProcessingService = requestProcessingService;
        _schemaResolverService = schemaResolverService;
    }

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request, CancellationToken cancellationToken = default)
    {
        return await _requestProcessingService.ExecuteWithConcurrencyControlAsync(
            ct => ValidateCoreAsync(request, ct),
            request.Options,
            cancellationToken);
    }

    public async Task<ValidationResult> ValidateWithSchemaUriAsync(object jsonData, string schemaUri, ValidationOptions? options = null, CancellationToken cancellationToken = default)
    {
        var request = new ValidationRequest
        {
            JsonData = jsonData,
            SchemaUri = schemaUri,
            Options = options
        };

        return await _requestProcessingService.ExecuteWithConcurrencyControlAsync(
            ct => ValidateCoreAsync(request, ct),
            options,
            cancellationToken);
    }

    public async Task<bool> IsValidAsync(ValidationRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _requestProcessingService.ExecuteWithConcurrencyControlAsync(
            ct => ValidateCoreAsync(request, ct),
            request.Options,
            cancellationToken);
        return result.IsValid;
    }

    private async Task<ValidationResult> ValidateCoreAsync(ValidationRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = new ValidationResult();

        try
        {
            _logger.LogInformation("Starting JSON validation for request");

            // Create timeout token
            using var timeoutCts = _requestProcessingService.CreateTimeoutToken(request.Options, cancellationToken);
            var effectiveToken = timeoutCts.Token;

            // Get JSON data and schema concurrently if possible
            var dataTask = GetJsonDataAsync(request, effectiveToken);
            var schemaTask = GetSchemaAsync(request, effectiveToken);

            var jsonData = await dataTask;
            var schema = await schemaTask;

            // Validate the JSON data
            // Format with indentation so validation error line numbers are accurate
            var jsonDataString = JsonConvert.SerializeObject(jsonData, Formatting.Indented);
            var validationErrors = await ValidateJsonAgainstSchemaAsync(jsonDataString, schema, request.Options);

            // Build result
            result.IsValid = !validationErrors.Any();
            result.Errors = validationErrors;
            result.SchemaVersion = "2020-12";
            result.Metadata = new ValidationMetadata
            {
                SchemaTitle = GetSchemaTitle(request, schema),
                SchemaDescription = GetSchemaDescription(request, schema),
                DataSize = jsonDataString.Length,
                ValidationTimestamp = DateTime.UtcNow,
                DataSource = !string.IsNullOrEmpty(request.DataUrl) ? request.DataUrl : "direct"
            };

            _logger.LogInformation("JSON validation completed. IsValid: {IsValid}, Errors: {ErrorCount}",
                result.IsValid, result.Errors.Count);
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Invalid argument during JSON validation");
            throw;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Invalid operation during JSON validation");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during JSON validation");
            result.IsValid = false;
            result.Errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Validation failed: {ex.Message}",
                ErrorCode = "VALIDATION_ERROR",
                Severity = "Error"
            });
        }
        finally
        {
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
        }

        return result;
    }

    public async Task<ValidationResult> ValidateSchemaAsync(object schema, CancellationToken cancellationToken = default)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = new ValidationResult();

        try
        {
            _logger.LogInformation("Starting schema validation");

            var schemaJson = JsonConvert.SerializeObject(schema);
            var jsonSchema = await _schemaResolverService.CreateSchemaFromJsonAsync(schemaJson, cancellationToken);

            // Basic schema validation
            var schemaValidationErrors = new List<ValidationError>();

            if (jsonSchema.Type == null)
            {
                schemaValidationErrors.Add(new ValidationError
                {
                    Path = "",
                    Message = "Schema should specify a type",
                    ErrorCode = "MISSING_TYPE",
                    Severity = "Warning"
                });
            }

            result.IsValid = !schemaValidationErrors.Any();
            result.Errors = schemaValidationErrors;
            result.SchemaVersion = "2020-12";
            result.Metadata = new ValidationMetadata
            {
                SchemaTitle = GetSchemaTitleFromObject(schema) ?? jsonSchema.Title,
                SchemaDescription = GetSchemaDescriptionFromObject(schema) ?? jsonSchema.Description,
                ValidationTimestamp = DateTime.UtcNow
            };

            _logger.LogInformation("Schema validation completed. IsValid: {IsValid}", result.IsValid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during schema validation");
            result.IsValid = false;
            result.Errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Schema validation failed: {ex.Message}",
                ErrorCode = "SCHEMA_VALIDATION_ERROR",
                Severity = "Error"
            });
        }
        finally
        {
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
        }

        return result;
    }

    private async Task<object> GetJsonDataAsync(ValidationRequest request, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(request.DataUrl))
        {
            return await FetchJsonDataFromUrlAsync(request.DataUrl, request.Options, cancellationToken);
        }
        else if (request.JsonData != null)
        {
            return request.JsonData;
        }
        else
        {
            throw new ArgumentException("Either JsonData or DataUrl must be provided");
        }
    }

    private async Task<JSchema> GetSchemaAsync(ValidationRequest request, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(request.SchemaUri))
        {
            return await LoadSchemaFromUriAsync(request.SchemaUri, request.Options, cancellationToken);
        }
        else if (request.Schema != null)
        {
            return await CreateSchemaFromObjectAsync(request.Schema);
        }
        else
        {
            throw new ArgumentException("Either Schema, SchemaUri, or SchemaId must be provided");
        }
    }

    private async Task<JSchema> LoadSchemaFromUriAsync(string schemaUri, ValidationOptions? options, CancellationToken cancellationToken)
    {
        return await _requestProcessingService.ExecuteWithRetryAsync(async (ct) =>
        {
            try
            {
                _logger.LogInformation("Loading schema from URI: {SchemaUri}", schemaUri);

                // Use PathParsingService for URI validation
                var validatedUri = await _pathParsingService.ValidateAndParseSchemaUriAsync(schemaUri, options);

                var response = await _httpClient.GetAsync(validatedUri, ct);
                response.EnsureSuccessStatusCode();
                var schemaJson = await response.Content.ReadAsStringAsync(ct);

                // Pass the validated URI as documentUri so JSchemaUrlResolver can resolve relative references
                return await _schemaResolverService.CreateSchemaFromJsonAsync(schemaJson, validatedUri.ToString(), ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load schema from URI: {SchemaUri}", schemaUri);
                throw new InvalidOperationException($"Failed to load schema from URI: {schemaUri}", ex);
            }
        }, options, cancellationToken);
    }

    private async Task<JSchema> CreateSchemaFromObjectAsync(object schema)
    {
        try
        {
            var schemaJson = JsonConvert.SerializeObject(schema);
            return await _schemaResolverService.CreateSchemaFromJsonAsync(schemaJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create schema from object");
            throw new InvalidOperationException("Failed to create schema from object", ex);
        }
    }

    private Task<List<ValidationError>> ValidateJsonAgainstSchemaAsync(string jsonData, JSchema schema, ValidationOptions? options)
    {
        var errors = new List<ValidationError>();
        var maxErrors = options?.MaxErrors ?? 100;

        try
        {
            // Parse JSON to validate format
            var jsonToken = JToken.Parse(jsonData);

            // Perform validation using Newtonsoft.Json.Schema
            bool isValid = jsonToken.IsValid(schema, out IList<string> errorMessages);

            if (!isValid)
            {
                // Use JSchema.Validate to get detailed validation errors
                var validationErrors = new List<ValidationError>();
                jsonToken.Validate(schema, (sender, args) =>
                {
                    validationErrors.Add(new ValidationError
                    {
                        Path = args.Path ?? "",
                        Message = args.Message,
                        ErrorCode = "VALIDATION_ERROR",
                        Severity = "Error"
                    });
                });

                errors.AddRange(validationErrors.Take(maxErrors));
            }
        }
        catch (JsonReaderException ex)
        {
            errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Invalid JSON format: {ex.Message}",
                ErrorCode = "INVALID_JSON",
                Severity = "Error"
            });
        }

        return Task.FromResult(errors);
    }

    private async Task<object> FetchJsonDataFromUrlAsync(string dataUrl, ValidationOptions? options, CancellationToken cancellationToken)
    {
        return await _requestProcessingService.ExecuteWithRetryAsync(async (ct) =>
        {
            try
            {
                _logger.LogInformation("Fetching JSON data from URL: {DataUrl}", dataUrl);

                // Use PathParsingService for URL validation
                var validatedUri = await _pathParsingService.ValidateAndParseDataUrlAsync(dataUrl, options);

                using var request = new HttpRequestMessage(HttpMethod.Get, validatedUri);

                var response = await _httpClient.SendAsync(request, ct);
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync(ct);

                // Parse and return the JSON data
                return JsonConvert.DeserializeObject<object>(content)
                    ?? throw new InvalidOperationException("Failed to deserialize JSON data from URL");
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request failed when fetching data from URL: {DataUrl}", dataUrl);
                throw new InvalidOperationException($"Failed to fetch data from URL: {dataUrl}", ex);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Invalid JSON received from URL: {DataUrl}", dataUrl);
                throw new InvalidOperationException($"Invalid JSON received from URL: {dataUrl}", ex);
            }
        }, options, cancellationToken);
    }

    private string? GetSchemaTitle(ValidationRequest request, JSchema schema)
    {
        // First try to get the title from the original schema object
        if (request.Schema != null)
        {
            try
            {
                var jObject = JObject.FromObject(request.Schema);
                var title = jObject["title"]?.ToString();
                if (!string.IsNullOrEmpty(title))
                {
                    return title;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to extract title from original schema object");
            }
        }

        // Fall back to JSchema title
        return schema.Title;
    }

    private string? GetSchemaDescription(ValidationRequest request, JSchema schema)
    {
        // First try to get the description from the original schema object
        if (request.Schema != null)
        {
            try
            {
                var jObject = JObject.FromObject(request.Schema);
                var description = jObject["description"]?.ToString();
                if (!string.IsNullOrEmpty(description))
                {
                    return description;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to extract description from original schema object");
            }
        }

        // Fall back to JSchema description
        return schema.Description;
    }

    private string? GetSchemaTitleFromObject(object? schemaObject)
    {
        if (schemaObject == null) return null;
        
        try
        {
            var jObject = JObject.FromObject(schemaObject);
            return jObject["title"]?.ToString();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract title from schema object");
            return null;
        }
    }

    private string? GetSchemaDescriptionFromObject(object? schemaObject)
    {
        if (schemaObject == null) return null;
        
        try
        {
            var jObject = JObject.FromObject(schemaObject);
            return jObject["description"]?.ToString();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract description from schema object");
            return null;
        }
    }

}


using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using OpenReferralApi.Core.Models;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;
using System.Diagnostics;
using ValidationError = OpenReferralApi.Core.Models.ValidationError;

namespace OpenReferralApi.Core.Services;

public interface IOpenApiValidationService
{
    Task<OpenApiValidationResult> ValidateOpenApiSpecificationAsync(OpenApiValidationRequest request, CancellationToken cancellationToken = default);
}

public class OpenApiValidationService : IOpenApiValidationService
{
    private readonly ILogger<OpenApiValidationService> _logger;
    private readonly HttpClient _httpClient;
    private readonly IJsonValidatorService _jsonValidatorService;
    private readonly ISchemaResolverService _schemaResolverService;
    private readonly IOpenApiDiscoveryService _discoveryService;

    public OpenApiValidationService(ILogger<OpenApiValidationService> logger, HttpClient httpClient, IJsonValidatorService jsonValidatorService, ISchemaResolverService schemaResolverService, IOpenApiDiscoveryService discoveryService)
    {
        _logger = logger;
        _httpClient = httpClient;
        _jsonValidatorService = jsonValidatorService;
        _schemaResolverService = schemaResolverService;
        _discoveryService = discoveryService;
    }

    public async Task<OpenApiValidationResult> ValidateOpenApiSpecificationAsync(OpenApiValidationRequest request, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new OpenApiValidationResult();

        try
        {
            _logger.LogInformation("Starting OpenAPI specification testing");

            // Ensure options has default values if not provided
            request.Options ??= new OpenApiValidationOptions();

            // Discover OpenAPI schema URL if not provided
            if (request.OpenApiSchema == null || string.IsNullOrEmpty(request.OpenApiSchema.Url))
            {
                if (!string.IsNullOrEmpty(request.BaseUrl))
                {
                    var (discoveredUrl, reason) = await _discoveryService.DiscoverOpenApiUrlAsync(request.BaseUrl, cancellationToken);
                    if (!string.IsNullOrEmpty(discoveredUrl))
                    {
                        _logger.LogInformation("Discovered OpenAPI schema URL: {Url} (Reason: {Reason})", discoveredUrl, reason);
                        request.OpenApiSchema ??= new OpenApiSchema();
                        request.OpenApiSchema.Url = discoveredUrl;
                        request.ProfileReason = reason;
                    }
                    else
                    {
                        throw new ArgumentException("Failed to discover OpenAPI schema URL from base URL");
                    }
                }
                else
                {
                    throw new ArgumentException("OpenAPI schema URL must be provided or BaseUrl must allow discovery");
                }
            }

            // Get OpenAPI specification
            JObject openApiSpec;
            if (!string.IsNullOrEmpty(request.OpenApiSchema?.Url))
            {
                var fetchedSchema = await FetchOpenApiSpecFromUrlAsync(request.OpenApiSchema.Url, request.OpenApiSchema.Authentication, cancellationToken);
                openApiSpec = JObject.Parse(fetchedSchema.ToString());
                // External references are already resolved by FetchOpenApiSpecFromUrlAsync
            }
            else
            {
                throw new ArgumentException("OpenAPI schema URL must be provided or BaseUrl must allow discovery");
            }

            // Validate the OpenAPI specification
            OpenApiSpecificationValidation? specValidation = null;
            if (request.Options.ValidateSpecification)
            {
                specValidation = await ValidateOpenApiSpecificationInternalAsync(openApiSpec, cancellationToken);
                result.SpecificationValidation = specValidation;
            }

            // Test endpoints if requested
            List<EndpointTestResult> endpointTests = new();
            if (request.Options.TestEndpoints && !string.IsNullOrEmpty(request.BaseUrl))
            {
                endpointTests = await TestEndpointsAsync(openApiSpec, request.BaseUrl, request.Options, request.DataSourceAuth, request.OpenApiSchema?.Url, cancellationToken);
                result.EndpointTests = endpointTests;
            }

            // Build summary
            result.Summary = BuildTestSummary(specValidation, endpointTests);
            result.IsValid = (specValidation?.IsValid ?? true) && result.Summary.FailedTests == 0;

            // Set metadata
            result.Metadata = new OpenApiValidationMetadata
            {
                BaseUrl = request.BaseUrl,
                TestTimestamp = DateTime.UtcNow,
                TestDuration = stopwatch.Elapsed,
                UserAgent = "OpenReferral-Validator/1.0",
                ProfileReason = request.ProfileReason
            };

            _logger.LogInformation("OpenAPI testing completed. IsValid: {IsValid}, Endpoints: {EndpointCount}",
                result.IsValid, result.EndpointTests.Count);

            // Honor option to exclude response bodies from the produced result (does not affect testing)
            if (!request.Options.IncludeResponseBody && result.EndpointTests != null)
            {
                foreach (var ep in result.EndpointTests)
                {
                    if (ep.TestResults == null) continue;
                    foreach (var tr in ep.TestResults)
                    {
                        tr.ResponseBody = null;
                    }
                }
            }

            // Honor option to exclude test results array from the produced result (does not affect testing)
            if (!request.Options.IncludeTestResults && result.EndpointTests != null)
            {
                foreach (var ep in result.EndpointTests)
                {
                    ep.TestResults.Clear();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during OpenAPI testing");
            result.IsValid = false;
            result.Summary = new OpenApiValidationSummary();
        }
        finally
        {
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
        }

        return result;
    }

    private async Task<OpenApiSpecificationValidation> ValidateOpenApiSpecificationInternalAsync(JObject openApiSpec, CancellationToken cancellationToken = default)
    {
        var validation = new OpenApiSpecificationValidation();
        var errors = new List<ValidationError>();

        try
        {
            _logger.LogInformation("Validating OpenAPI specification");

            // We already have a JObject, so we can use it directly
            await ValidateOpenApiSpecObjectAsync(openApiSpec, validation, errors, null, cancellationToken);

            // Add detailed analysis
            validation.SchemaAnalysis = AnalyzeSchemaStructure(openApiSpec);
            validation.QualityMetrics = AnalyzeQualityMetrics(openApiSpec);
            validation.Recommendations = GenerateRecommendations(openApiSpec, errors);

            return validation;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during OpenAPI validation");
            errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Validation error: {ex.Message}",
                ErrorCode = "VALIDATION_ERROR",
                Severity = "Error"
            });

            validation.IsValid = false;
            validation.Errors = errors;
            return validation;
        }
    }

    /// <summary>
    /// Common validation logic for OpenAPI specifications
    /// </summary>
    private async Task ValidateOpenApiSpecObjectAsync(
        JObject specObject,
        OpenApiSpecificationValidation validation,
        List<ValidationError> errors,
        JSchema? originalSchema = null,
        CancellationToken cancellationToken = default)
    {
        // Check for required OpenAPI fields
        if (!specObject.ContainsKey("openapi") && !specObject.ContainsKey("swagger"))
        {
            errors.Add(new ValidationError
            {
                Path = "",
                Message = "OpenAPI specification must contain 'openapi' or 'swagger' field",
                ErrorCode = "MISSING_OPENAPI_VERSION",
                Severity = "Error"
            });
        }

        // Extract version
        if (specObject.ContainsKey("openapi"))
        {
            validation.OpenApiVersion = specObject["openapi"]?.ToString();
        }
        else if (specObject.ContainsKey("swagger"))
        {
            validation.OpenApiVersion = specObject["swagger"]?.ToString();
        }

        // Check for info section
        if (!specObject.ContainsKey("info"))
        {
            errors.Add(new ValidationError
            {
                Path = "info",
                Message = "OpenAPI specification must contain 'info' section",
                ErrorCode = "MISSING_INFO",
                Severity = "Error"
            });
        }
        else
        {
            var info = specObject["info"];
            validation.Title = info?["title"]?.ToString();
            validation.Version = info?["version"]?.ToString();

            if (string.IsNullOrEmpty(validation.Title))
            {
                errors.Add(new ValidationError
                {
                    Path = "info.title",
                    Message = "API title is recommended",
                    ErrorCode = "MISSING_TITLE",
                    Severity = "Warning"
                });
            }

            if (string.IsNullOrEmpty(validation.Version))
            {
                errors.Add(new ValidationError
                {
                    Path = "info.version",
                    Message = "API version is recommended",
                    ErrorCode = "MISSING_VERSION",
                    Severity = "Warning"
                });
            }
        }

        // Check for paths section
        if (!specObject.ContainsKey("paths"))
        {
            errors.Add(new ValidationError
            {
                Path = "paths",
                Message = "OpenAPI specification must contain 'paths' section",
                ErrorCode = "MISSING_PATHS",
                Severity = "Error"
            });
        }
        else
        {
            var paths = specObject["paths"];
            if (paths is JObject pathsObject)
            {
                validation.EndpointCount = pathsObject.Count;

                if (validation.EndpointCount == 0)
                {
                    errors.Add(new ValidationError
                    {
                        Path = "paths",
                        Message = "No endpoints defined in paths section",
                        ErrorCode = "NO_ENDPOINTS",
                        Severity = "Warning"
                    });
                }
            }
        }

        // Validate JSON Schema compliance - use original schema if available, otherwise use specObject
        try
        {
            var schemaUri = GetOpenApiSchemaUri(specObject, validation.OpenApiVersion);
            if (!string.IsNullOrEmpty(schemaUri))
            {
                object dataForValidation = originalSchema != null ? originalSchema : specObject;
                var validationRequest = new ValidationRequest
                {
                    JsonData = dataForValidation,
                    SchemaUri = schemaUri
                };

                var schemaValidation = await _jsonValidatorService.ValidateAsync(validationRequest, cancellationToken);
                if (!schemaValidation.IsValid)
                {
                    foreach (var error in schemaValidation.Errors)
                    {
                        errors.Add(error);
                    }
                }

                // Log which schema was used for validation
                var dialectInfo = specObject.ContainsKey("jsonSchemaDialect")
                    ? $"using jsonSchemaDialect: {specObject["jsonSchemaDialect"]}"
                    : $"using version-based schema for OpenAPI {validation.OpenApiVersion}";
                _logger.LogDebug("Validated OpenAPI specification {DialogInfo} with schema URI: {SchemaUri}", dialectInfo, schemaUri);
            }
            else
            {
                var dialectInfo = specObject.ContainsKey("jsonSchemaDialect")
                    ? $"jsonSchemaDialect '{specObject["jsonSchemaDialect"]}' is not supported"
                    : $"version '{validation.OpenApiVersion}' is not supported";

                errors.Add(new ValidationError
                {
                    Path = "",
                    Message = $"No schema validation available: {dialectInfo}. Supported versions: OpenAPI 3.0.x, 3.1.x, Swagger 2.0, and common JSON Schema dialects (2020-12, 2019-09, draft-07, draft-06, draft-04)",
                    ErrorCode = "UNSUPPORTED_SCHEMA_VERSION",
                    Severity = "Warning"
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not validate against OpenAPI schema");
            errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Could not validate against OpenAPI schema: {ex.Message}",
                ErrorCode = "SCHEMA_VALIDATION_FAILED",
                Severity = "Warning"
            });
        }

        validation.IsValid = !errors.Any();
        validation.Errors = errors;

        _logger.LogInformation("OpenAPI specification validation completed. IsValid: {IsValid}, Errors: {ErrorCount}",
            validation.IsValid, validation.Errors.Count);
    }

    private async Task<List<EndpointTestResult>> TestEndpointsAsync(JObject openApiSpec, string baseUrl, OpenApiValidationOptions options, DataSourceAuthentication? authentication, string? documentUri, CancellationToken cancellationToken = default)
    {
        var results = new List<EndpointTestResult>();

        try
        {
            _logger.LogInformation("Testing OpenAPI endpoints with intelligent dependency ordering");

            // We already have a JObject, so use it directly
            if (!openApiSpec.ContainsKey("paths"))
            {
                _logger.LogWarning("No paths found in OpenAPI specification");
                return results;
            }

            var paths = openApiSpec["paths"];
            if (paths is not JObject pathsObject)
            {
                return results;
            }

            // Group and order endpoints with intelligent dependency handling
            var endpointGroups = GroupEndpointsByDependencies(pathsObject, options);

            // Shared dictionary for ID extraction and usage across dependent endpoints
            // This dictionary is populated by collection endpoints and consumed by parameterized endpoints
            var extractedIds = new ConcurrentDictionary<string, List<string>>();

            _logger.LogInformation("Found {GroupCount} endpoint groups for dependency-aware testing", endpointGroups.Count);

            // Test endpoints in dependency order - collection endpoints first, then parameterized
            foreach (var group in endpointGroups)
            {
                _logger.LogInformation("Testing endpoint group: {GroupName} with {Count} endpoints", group.RootPath, group.Endpoints.Count);

                var semaphore = new SemaphoreSlim(options.MaxConcurrentRequests, options.MaxConcurrentRequests);

                // PHASE 1: Test collection endpoints sequentially to extract IDs
                // These endpoints (e.g., GET /users) return collections with IDs that are stored in extractedIds
                foreach (var endpoint in group.CollectionEndpoints)
                {
                    var result = await TestSingleEndpointWithIdExtractionAsync(endpoint.Path, endpoint.Method, endpoint.Operation,
                        baseUrl, options, authentication, extractedIds, semaphore, openApiSpec, documentUri, endpoint.PathItem, cancellationToken);
                    results.Add(result);
                }

                // PHASE 2: Test parameterized endpoints concurrently using extracted IDs
                // These endpoints (e.g., GET /users/{id}) use IDs from the extractedIds dictionary
                var parameterizedTasks = new List<Task<EndpointTestResult>>();
                foreach (var endpoint in group.ParameterizedEndpoints)
                {
                    var task = TestSingleEndpointWithIdSubstitutionAsync(endpoint.Path, endpoint.Method, endpoint.Operation,
                        baseUrl, options, authentication, extractedIds, semaphore, openApiSpec, documentUri, endpoint.PathItem, cancellationToken);
                    parameterizedTasks.Add(task);
                }

                var parameterizedResults = await Task.WhenAll(parameterizedTasks);
                results.AddRange(parameterizedResults);

                _logger.LogInformation("Completed group {GroupName}: {CollectionCount} collection + {ParamCount} parameterized endpoints",
                    group.RootPath, group.CollectionEndpoints.Count, group.ParameterizedEndpoints.Count);
            }

            _logger.LogInformation("Completed testing {Count} endpoints with intelligent dependency ordering", results.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during dependency-aware endpoint testing");
        }

        return results;
    }

    /// <summary>
    /// Gets the appropriate schema URI for validating an OpenAPI specification.
    /// First checks for jsonSchemaDialect field (OpenAPI 3.1+), then falls back to version-based selection.
    /// </summary>
    /// <param name="specObject">The parsed OpenAPI specification object</param>
    /// <param name="version">The OpenAPI or Swagger version string</param>
    /// <returns>The schema URI for validation, or null if version is not supported</returns>
    private static string? GetOpenApiSchemaUri(JObject specObject, string? version)
    {
        // First, check if the spec explicitly declares a jsonSchemaDialect (OpenAPI 3.1+)
        if (specObject.ContainsKey("jsonSchemaDialect"))
        {
            var dialect = specObject["jsonSchemaDialect"]?.ToString();
            if (!string.IsNullOrEmpty(dialect))
            {
                // Only return the dialect if it's a known JSON Schema dialect
                if (IsKnownJsonSchemaDialect(dialect))
                {
                    return dialect;
                }
                // For unknown/custom dialects, fall back to version-based schema selection
            }
        }

        // Fallback to version-based schema selection
        return "https://json-schema.org/draft/2020-12/schema"; // Default to latest known JSON Schema draft
    }

    /// <summary>
    /// Checks if the provided dialect URI is a known/supported JSON Schema dialect.
    /// </summary>
    /// <param name="dialect">The JSON Schema dialect URI</param>
    /// <returns>True if the dialect is known and supported, false otherwise</returns>
    private static bool IsKnownJsonSchemaDialect(string dialect)
    {
        return dialect switch
        {
            "https://json-schema.org/draft/2020-12/schema" => true,
            "https://json-schema.org/draft/2019-09/schema" => true,
            "http://json-schema.org/draft-07/schema#" => true,
            "http://json-schema.org/draft-06/schema#" => true,
            "http://json-schema.org/draft-04/schema#" => true,
            _ => false
        };
    }

    private async Task<EndpointTestResult> TestSingleEndpointAsync(string path, string method, JObject operation, string baseUrl, OpenApiValidationOptions options, DataSourceAuthentication? authentication, SemaphoreSlim semaphore, JObject openApiDocument, string? documentUri, JObject pathItem, CancellationToken cancellationToken, string? testedId = null)
    {
        await semaphore.WaitAsync(cancellationToken);

        // Resolve all parameter references upfront (includes path-level and operation-level params)
        var resolvedParams = ResolveOperationParameters(operation, pathItem, openApiDocument);

        var result = new EndpointTestResult
        {
            Path = path,
            Method = method,
            Name = operation["name"]?.ToString(),
            OperationId = operation["operationId"]?.ToString(),
            Summary = operation["summary"]?.ToString(),
            IsOptional = operation.IsOptionalEndpoint(),
            Status = "NotTested"
        };

        try
        {
            bool isOptional = operation.IsOptionalEndpoint();
            bool skipOptional = options.TestOptionalEndpoints == false && isOptional;
            if (skipOptional)
            {
                result.Status = "Skipped";
                return result;
            }

            // Check if this endpoint has pagination support
            _logger.LogDebug("Checking pagination support for {Method} {Path}", method, path);
            bool hasPagination = method == "GET" && HasPageParameter(resolvedParams);
            _logger.LogInformation("{Method} {Path}: hasPagination={HasPagination}", method, path, hasPagination);

            if (hasPagination)
            {
                // Test pagination: first page, middle page(s), last page
                await TestPaginatedEndpointAsync(result, path, method, operation, baseUrl, options, authentication, resolvedParams, openApiDocument, documentUri, pathItem, cancellationToken);
            }
            else
            {
                // Standard single-request testing
                var fullUrl = BuildFullUrl(baseUrl, path, resolvedParams, options);
                var testResult = await ExecuteHttpRequestAsync(fullUrl, method, operation, options, authentication, cancellationToken, testedId);

                result.TestResults.Add(testResult);
                result.IsTested = true;

                // Check for non-success status codes and handle based on endpoint requirements
                if (!testResult.IsSuccess)
                {
                    var isOptionalEndpoint = pathItem.IsOptionalEndpoint();
                    var statusCode = testResult.ResponseStatusCode ?? 0;
                    var errorMessage = $"Endpoint returned {statusCode} status code";

                    if (isOptionalEndpoint)
                    {
                        // For optional endpoints, add validation warning instead of error
                        if (testResult.ValidationResult == null)
                        {
                            testResult.ValidationResult = new ValidationResult
                            {
                                IsValid = false,
                                Errors = new List<ValidationError>(),
                                SchemaVersion = string.Empty,
                                Duration = TimeSpan.Zero
                            };
                        }
                        testResult.ValidationResult.Errors.Add(new ValidationError
                        {
                            Path = path,
                            Message = $"Optional endpoint {method} {path} returned non-success status {statusCode}. This may indicate the endpoint is not implemented, which is acceptable for optional endpoints.",
                            ErrorCode = "OPTIONAL_ENDPOINT_NON_SUCCESS",
                            Severity = "Warning"
                        });
                        result.Status = "Warning";
                    }
                    else
                    {
                        // For required endpoints, add validation error
                        if (testResult.ValidationResult == null)
                        {
                            testResult.ValidationResult = new ValidationResult
                            {
                                IsValid = false,
                                Errors = new List<ValidationError>(),
                                SchemaVersion = string.Empty,
                                Duration = TimeSpan.Zero
                            };
                        }
                        testResult.ValidationResult.Errors.Add(new ValidationError
                        {
                            Path = path,
                            Message = $"Required endpoint {method} {path} returned non-success status {statusCode}. Expected 2xx status code.",
                            ErrorCode = "REQUIRED_ENDPOINT_FAILED",
                            Severity = "Error"
                        });
                        result.Status = "Failed";
                    }
                }

                // Validate response if schema is defined
                if (testResult.IsSuccess && testResult.ResponseBody != null)
                {
                    await ValidateResponseAsync(testResult, operation, openApiDocument, documentUri, cancellationToken);
                    result.Status = testResult.ValidationResult != null && testResult.ValidationResult.IsValid ? "Success" : "Failed";
                }


                // Optional endpoint warning logic (only apply if status wasn't already set by non-success handling)
                if (result.Status == "NotTested" || result.Status == "Success" || result.Status == "Failed")
                {
                    if (isOptional && options.TestOptionalEndpoints && options.TreatOptionalEndpointsAsWarnings)
                    {
                        // If there are validation errors, report as warnings
                        if (testResult.ValidationResult != null && !testResult.ValidationResult.IsValid)
                        {
                            result.Status = "Warning";
                        }
                        else if (result.Status != "Warning")
                        {
                            result.Status = testResult.IsSuccess ? "Success" : "Warning";
                        }
                    }
                    else if (result.Status != "Warning" && result.Status != "Failed")
                    {
                        result.Status = testResult.IsSuccess ? "Success" : "Failed";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error testing endpoint {Method} {Path}", method, path);
            result.TestResults.Add(new HttpTestResult
            {
                RequestUrl = $"{baseUrl}{path}",
                RequestMethod = method,
                IsSuccess = false,
                ErrorMessage = ex.Message,
                ResponseTime = TimeSpan.Zero
            });
            result.Status = "Error";
        }
        finally
        {
            semaphore.Release();
        }

        return result;
    }

    /// <summary>
    /// Tests a paginated endpoint by requesting the first page, last page, and a page in the middle.
    /// Validates pagination metadata and warns if the feed contains no data.
    /// </summary>
    private async Task TestPaginatedEndpointAsync(
        EndpointTestResult result,
        string path,
        string method,
        JObject operation,
        string baseUrl,
        OpenApiValidationOptions options,
        DataSourceAuthentication? auth,
        JArray resolvedParams,
        JObject openApiDocument,
        string? documentUri,
        JObject pathItem,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Testing paginated endpoint: {Method} {Path}", method, path);

        result.IsTested = true;

        // Test first page (page=1)
        _logger.LogDebug("Testing first page for {Path}", path);
        var firstPageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: 1);
        var firstPageResult = await ExecuteHttpRequestAsync(firstPageUrl, method, operation, options, auth, cancellationToken);
        result.TestResults.Add(firstPageResult);

        if (!firstPageResult.IsSuccess)
        {
            var isOptionalEndpoint = pathItem.IsOptionalEndpoint();
            var statusCode = firstPageResult.ResponseStatusCode ?? 0;

            if (isOptionalEndpoint)
            {
                firstPageResult.ValidationResult!.Errors.Add(new ValidationError
                {
                    Path = path,
                    Message = $"Optional endpoint {method} {path} returned non-success status {statusCode}. This may indicate the endpoint is not implemented, which is acceptable for optional endpoints.",
                    ErrorCode = "OPTIONAL_ENDPOINT_NON_SUCCESS",
                    Severity = "Warning"
                });
                result.Status = "Warning";
            }
            else
            {
                firstPageResult.ValidationResult!.Errors.Add(new ValidationError
                {
                    Path = path,
                    Message = $"Required endpoint {method} {path} returned non-success status {statusCode}. Expected 2xx status code.",
                    ErrorCode = "REQUIRED_ENDPOINT_FAILED",
                    Severity = "Error"
                });
                result.Status = "Failed";
            }
            return;
        }

        // Validate first page response schema
        if (firstPageResult.ResponseBody != null)
        {
            await ValidateResponseAsync(firstPageResult, operation, openApiDocument, documentUri, cancellationToken);
        }

        // Try to determine total pages and check for empty feed
        var paginationInfo = ExtractPaginationInfo(firstPageResult.ResponseBody);

        // Warn if feed returns no rows
        if (paginationInfo.ItemCount == 0)
        {
            firstPageResult.ValidationResult!.Errors.Add(new ValidationError
            {
                Path = path,
                Message = $"Paginated endpoint {method} {path} returned 0 items. Consider verifying if this is expected or if the feed should contain data.",
                ErrorCode = "EMPTY_FEED_WARNING",
                Severity = "Warning"
            });
            firstPageResult.ValidationResult.IsValid = false;
            _logger.LogWarning("Paginated endpoint {Path} returned empty feed (0 items)", path);
            return; // No further pagination testing needed for empty feeds
        }

        if (paginationInfo.TotalPages.HasValue && paginationInfo.TotalPages.Value > 1)
        {
            var totalPages = paginationInfo.TotalPages.Value;
            _logger.LogInformation("Endpoint {Path} has {TotalPages} pages, testing pagination", path, totalPages);

            // Test middle page if there are more than 2 pages
            if (totalPages > 2)
            {
                var middlePage = totalPages / 2;
                _logger.LogDebug("Testing middle page {PageNumber} for {Path}", middlePage, path);
                var middlePageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: middlePage);
                var middlePageResult = await ExecuteHttpRequestAsync(middlePageUrl, method, operation, options, auth, cancellationToken);
                result.TestResults.Add(middlePageResult);

                if (middlePageResult.IsSuccess && middlePageResult.ResponseBody != null)
                {
                    await ValidateResponseAsync(middlePageResult, operation, openApiDocument, documentUri, cancellationToken);
                }
            }

            // Test last page
            _logger.LogDebug("Testing last page {PageNumber} for {Path}", totalPages, path);
            var lastPageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: totalPages);
            var lastPageResult = await ExecuteHttpRequestAsync(lastPageUrl, method, operation, options, auth, cancellationToken);
            result.TestResults.Add(lastPageResult);

            if (lastPageResult.IsSuccess && lastPageResult.ResponseBody != null)
            {
                await ValidateResponseAsync(lastPageResult, operation, openApiDocument, documentUri, cancellationToken);
            }
        }
        else
        {
            _logger.LogDebug("Endpoint {Path} has only 1 page or pagination info not available, skipping additional page tests", path);
        }
    }

    /// <summary>
    /// Extracts pagination information from a response body to determine total pages and item count
    /// </summary>
    private (int? TotalPages, int ItemCount) ExtractPaginationInfo(string? responseBody)
    {
        if (string.IsNullOrEmpty(responseBody))
        {
            return (null, 0);
        }

        try
        {
            var json = JToken.Parse(responseBody);
            int? totalPages = null;
            int itemCount = 0;

            // Try to find total_pages field (common in paginated APIs)
            var totalPagesToken = json.SelectToken("$.total_pages") ??
                                  json.SelectToken("$.totalPages") ??
                                  json.SelectToken("$.pagination.total_pages") ??
                                  json.SelectToken("$.pagination.totalPages") ??
                                  json.SelectToken("$.meta.total_pages") ??
                                  json.SelectToken("$.meta.totalPages");

            if (totalPagesToken != null && int.TryParse(totalPagesToken.ToString(), out var pages))
            {
                totalPages = pages;
            }

            // Count items in common collection properties
            if (json is JArray array)
            {
                itemCount = array.Count;
            }
            else if (json is JObject obj)
            {
                // Check common collection property names
                foreach (var propName in new[] { "data", "items", "results", "content", "contents" })
                {
                    if (obj[propName] is JArray items)
                    {
                        itemCount = items.Count;
                        break;
                    }
                }

                // Also check for size/count fields
                if (itemCount == 0)
                {
                    var sizeToken = obj["size"] ?? obj["count"] ?? obj["length"];
                    if (sizeToken != null && int.TryParse(sizeToken.ToString(), out var size))
                    {
                        itemCount = size;
                    }
                }
            }

            return (totalPages, itemCount);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract pagination info from response");
            return (null, 0);
        }
    }

    private string BuildFullUrl(string baseUrl, string path, JArray resolvedParams, OpenApiValidationOptions options, int? pageNumber = null)
    {
        var url = $"{baseUrl.TrimEnd('/')}{path}";

        // Add page parameter if specified
        if (pageNumber.HasValue && HasPageParameter(resolvedParams))
        {
            var separator = url.Contains('?') ? "&" : "?";
            url += $"{separator}page={pageNumber.Value}";
        }

        return url;
    }

    /// <summary>
    /// Checks if the resolved parameters array contains a 'page' query parameter.
    /// Parameters should already be resolved (references expanded, path and operation params merged).
    /// </summary>
    private bool HasPageParameter(JArray resolvedParams)
    {
        _logger.LogDebug("Checking {Count} parameters for 'page' parameter", resolvedParams.Count);
        foreach (var param in resolvedParams)
        {
            if (param is JObject paramObj)
            {
                var name = paramObj["name"]?.ToString();
                var inLocation = paramObj["in"]?.ToString();
                _logger.LogDebug("Checking param: name={Name}, in={In}", name, inLocation);

                if (name?.Equals("page", StringComparison.OrdinalIgnoreCase) == true &&
                    inLocation?.Equals("query", StringComparison.OrdinalIgnoreCase) == true)
                {
                    _logger.LogInformation("Found 'page' query parameter - endpoint supports pagination");
                    return true;
                }
            }
        }
        _logger.LogDebug("No 'page' parameter found - endpoint does not support pagination");
        return false;
    }

    /// <summary>
    /// Merges path-level and operation-level parameters.
    /// Returns a JArray of parameter objects (references already resolved upstream).
    /// </summary>
    private JArray ResolveOperationParameters(JObject operation, JObject pathItem, JObject openApiDocument)
    {
        var resolvedParams = new JArray();

        // Add path-level parameters first (these are inherited by all operations)
        if (pathItem["parameters"] is JArray pathParams)
        {
            _logger.LogDebug("Found {Count} path-level parameters", pathParams.Count);
            foreach (var param in pathParams)
            {
                resolvedParams.Add(param);
                _logger.LogDebug("Path-level param: {Param}", param.ToString());
            }
        }

        // Add operation-level parameters (these can override path-level params)
        if (operation["parameters"] is JArray operationParams)
        {
            _logger.LogDebug("Found {Count} operation-level parameters", operationParams.Count);
            foreach (var param in operationParams)
            {
                resolvedParams.Add(param);
                _logger.LogDebug("Operation-level param: {Param}", param.ToString());
            }
        }

        _logger.LogDebug("Total resolved parameters: {Count}", resolvedParams.Count);
        return resolvedParams;
    }

    private async Task<HttpTestResult> ExecuteHttpRequestAsync(string url, string method, JObject operation, OpenApiValidationOptions options, DataSourceAuthentication? authentication, CancellationToken cancellationToken, string? testedId = null)
    {
        var testResult = new HttpTestResult
        {
            RequestUrl = url,
            RequestMethod = method,
            TestedId = testedId,
            ValidationResult = new ValidationResult()
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), url);

            // Apply authentication if not skipped and auth is provided
            if (!options.SkipAuthentication && authentication != null)
            {
                ApplyAuthenticationHeaders(request, authentication);
            }

            // Set timeout
            var timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);

            // Use the injected HttpClient so test HttpMessageHandler mocks are respected.
            TimeSpan dnsLookup = TimeSpan.Zero, tcpConnection = TimeSpan.Zero, tlsHandshake = TimeSpan.Zero;
            var sendStart = Stopwatch.StartNew();
            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            var timeToHeaders = sendStart.Elapsed;

            // Prepare to read content and measure transfer time
            string responseBody = string.Empty;
            var contentTransferStopwatch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var responseStream = await response.Content.ReadAsStreamAsync(cts.Token);
                using var ms = new MemoryStream();
                await responseStream.CopyToAsync(ms, 81920, cts.Token);
                contentTransferStopwatch.Stop();
                responseBody = Encoding.UTF8.GetString(ms.ToArray());
            }
            catch (OperationCanceledException)
            {
                contentTransferStopwatch.Stop();
                responseBody = string.Empty;
            }

            // Stop the overall timers
            sendStart.Stop();

            // Populate basic result fields
            testResult.ResponseTime = timeToHeaders + contentTransferStopwatch.Elapsed;
            testResult.ResponseStatusCode = (int)response.StatusCode;
            testResult.IsSuccess = response.IsSuccessStatusCode;
            testResult.ResponseBody = responseBody;

            // Populate performance metrics (include best-effort DNS/TCP/TLS measurements if available)
            testResult.PerformanceMetrics = new EndpointPerformanceMetrics
            {
                DnsLookup = dnsLookup,
                TcpConnection = tcpConnection,
                TlsHandshake = tlsHandshake,
                ServerProcessing = timeToHeaders,
                ContentTransfer = contentTransferStopwatch.Elapsed
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            testResult.ResponseTime = stopwatch.Elapsed;
            testResult.IsSuccess = false;
            testResult.ErrorMessage = ex.Message;
        }

        return testResult;
    }

    private async Task ValidateResponseAsync(HttpTestResult testResult, JObject operation, JObject openApiDocument, string? documentUri, CancellationToken cancellationToken)
    {
        try
        {
            if (operation.ContainsKey("responses"))
            {
                var responses = operation["responses"];
                if (responses is JObject responsesObject)
                {
                    var statusCode = testResult.ResponseStatusCode?.ToString() ?? "default";
                    var responseSchema = responsesObject[statusCode] ?? responsesObject["default"];

                    if (responseSchema is JObject responseSchemaObject && responseSchemaObject.ContainsKey("content"))
                    {
                        var content = responseSchemaObject["content"];
                        if (content is JObject contentObject)
                        {
                            // Find JSON content type
                            var jsonContent = contentObject.Properties()
                                .FirstOrDefault(p => p.Name.Contains("application/json"));

                            if (jsonContent?.Value is JObject jsonContentObject && jsonContentObject.ContainsKey("schema"))
                            {
                                var schema = jsonContentObject["schema"];
                                if (schema != null)
                                {
                                    var schemaJson = schema.ToString();
                                    _logger.LogDebug("validating against schemaJson: {schemaJson}", schemaJson);
                                    // Use standard validation - SchemaResolverService handles all reference resolution
                                    var validationRequest = new ValidationRequest
                                    {
                                        JsonData = JsonConvert.DeserializeObject(testResult.ResponseBody ?? "{}"),
                                        Schema = schema
                                    };
                                    var validationResult = await _jsonValidatorService.ValidateAsync(validationRequest, cancellationToken);
                                    testResult.ValidationResult = validationResult;
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not validate response for {Url}", testResult.RequestUrl);
        }
    }

    /// <summary>
    /// Validates JSON data against a JSchema directly, similar to JsonValidatorService but without the full request processing
    /// </summary>
    private List<ValidationError> ValidateJsonAgainstSchema(string jsonData, JSchema schema)
    {
        var errors = new List<ValidationError>();

        try
        {
            // Parse JSON to validate format
            var jsonToken = JToken.Parse(jsonData);

            // Perform validation using Newtonsoft.Json.Schema
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

            errors.AddRange(validationErrors);
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
        catch (Exception ex)
        {
            errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Schema validation error: {ex.Message}",
                ErrorCode = "SCHEMA_VALIDATION_ERROR",
                Severity = "Error"
            });
        }

        return errors;
    }

    private async Task<JSchema> FetchOpenApiSpecFromUrlAsync(string specUrl, DataSourceAuthentication? auth, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Fetching OpenAPI specification from URL: {SpecUrl}", specUrl);

            if (!Uri.IsWellFormedUriString(specUrl, UriKind.Absolute))
            {
                throw new ArgumentException($"Invalid OpenAPI spec URL: {specUrl}");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, specUrl);

            // Apply authentication if provided
            if (auth != null)
            {
                ApplyAuthentication(request, auth);
            }

            var response = await _httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync(cancellationToken);

            // Use SchemaResolverService for consistent reference resolution and JSchema creation
            // Pass authentication so nested schema references can also be authenticated
            return await _schemaResolverService.CreateSchemaFromJsonAsync(content, specUrl, auth, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch OpenAPI specification from URL: {SpecUrl}", specUrl);
            throw new InvalidOperationException($"Failed to fetch OpenAPI specification from URL: {specUrl}", ex);
        }
    }

    private void ApplyAuthentication(HttpRequestMessage request, DataSourceAuthentication auth)
    {
        // Apply API Key authentication
        if (!string.IsNullOrEmpty(auth.ApiKey))
        {
            request.Headers.Add(auth.ApiKeyHeader, auth.ApiKey);
            _logger.LogDebug("Applied API Key authentication with header: {Header}", auth.ApiKeyHeader);
        }

        // Apply Bearer Token authentication
        if (!string.IsNullOrEmpty(auth.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.BearerToken);
            _logger.LogDebug("Applied Bearer Token authentication");
        }

        // Apply Basic authentication
        if (auth.BasicAuth != null && !string.IsNullOrEmpty(auth.BasicAuth.Username))
        {
            var credentials = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{auth.BasicAuth.Username}:{auth.BasicAuth.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            _logger.LogDebug("Applied Basic authentication for user: {Username}", auth.BasicAuth.Username);
        }

        // Apply custom headers
        if (auth.CustomHeaders != null)
        {
            foreach (var header in auth.CustomHeaders)
            {
                request.Headers.Add(header.Key, header.Value);
                _logger.LogDebug("Applied custom header: {HeaderName}", header.Key);
            }
        }
    }

    private OpenApiValidationSummary BuildTestSummary(OpenApiSpecificationValidation? specValidation, List<EndpointTestResult> endpointTests)
    {
        var summary = new OpenApiValidationSummary
        {
            TotalEndpoints = endpointTests.Count,
            TestedEndpoints = endpointTests.Count(e => e.IsTested),
            SuccessfulTests = endpointTests.Count(e => e.Status == "Success"),
            FailedTests = endpointTests.Count(e => e.Status == "Failed" || e.Status == "Error"),
            SkippedTests = endpointTests.Count(e => e.Status == "NotTested" || e.Status == "Skipped"),
            TotalRequests = endpointTests.Sum(e => e.TestResults.Count),
            SpecificationValid = specValidation?.IsValid ?? true
        };

        var responseTimes = endpointTests
            .SelectMany(e => e.TestResults)
            .Where(r => r.ResponseTime > TimeSpan.Zero)
            .Select(r => r.ResponseTime);

        if (responseTimes.Any())
        {
            summary.AverageResponseTime = TimeSpan.FromMilliseconds(responseTimes.Average(rt => rt.TotalMilliseconds));
        }

        return summary;
    }

    /// <summary>
    /// Analyzes the structure of the OpenAPI specification components
    /// </summary>
    private OpenApiSchemaAnalysis AnalyzeSchemaStructure(JObject specObject)
    {
        var analysis = new OpenApiSchemaAnalysis();

        try
        {
            // Analyze components section if it exists (OpenAPI 3.x)
            if (specObject.ContainsKey("components"))
            {
                var components = specObject["components"];
                if (components is JObject componentsObject)
                {
                    analysis.ComponentCount = 1;

                    // Count schemas
                    if (componentsObject.ContainsKey("schemas"))
                    {
                        var schemas = componentsObject["schemas"];
                        if (schemas is JObject schemasObject)
                        {
                            analysis.SchemaCount = schemasObject.Count;
                        }
                    }

                    // Count responses
                    if (componentsObject.ContainsKey("responses"))
                    {
                        var responses = componentsObject["responses"];
                        if (responses is JObject responsesObject)
                        {
                            analysis.ResponseCount = responsesObject.Count;
                        }
                    }

                    // Count parameters
                    if (componentsObject.ContainsKey("parameters"))
                    {
                        var parameters = componentsObject["parameters"];
                        if (parameters is JObject parametersObject)
                        {
                            analysis.ParameterCount = parametersObject.Count;
                        }
                    }

                    // Count request bodies
                    if (componentsObject.ContainsKey("requestBodies"))
                    {
                        var requestBodies = componentsObject["requestBodies"];
                        if (requestBodies is JObject requestBodiesObject)
                        {
                            analysis.RequestBodyCount = requestBodiesObject.Count;
                        }
                    }
                }
            }

            // Analyze definitions section for Swagger 2.0
            if (specObject.ContainsKey("definitions"))
            {
                var definitions = specObject["definitions"];
                if (definitions is JObject definitionsObject)
                {
                    analysis.SchemaCount = definitionsObject.Count;
                }
            }

            // Count references (simplified)
            var specJson = specObject.ToString();
            var refMatches = Regex.Matches(specJson, "\\$ref");
            analysis.ReferencesResolved = refMatches.Count;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error analyzing schema structure");
        }
        return analysis;
    }

    /// <summary>
    /// Analyzes quality metrics of the OpenAPI specification
    /// </summary>
    private OpenApiQualityMetrics AnalyzeQualityMetrics(JObject specObject)
    {
        var metrics = new OpenApiQualityMetrics();

        try
        {
            if (specObject.ContainsKey("paths"))
            {
                var paths = specObject["paths"];
                if (paths is JObject pathsObject)
                {
                    int totalEndpoints = 0;
                    int endpointsWithDescription = 0;
                    int endpointsWithSummary = 0;
                    int endpointsWithExamples = 0;
                    int totalParameters = 0;
                    int parametersWithDescription = 0;
                    int totalResponseCodes = 0;
                    int responseCodesDocumented = 0;

                    foreach (var path in pathsObject.Properties())
                    {
                        if (path.Value is JObject pathObject)
                        {
                            foreach (var method in pathObject.Properties())
                            {
                                if (method.Value is JObject operationObject)
                                {
                                    totalEndpoints++;

                                    if (operationObject.ContainsKey("description") &&
                                        !string.IsNullOrWhiteSpace(operationObject["description"]?.ToString()))
                                    {
                                        endpointsWithDescription++;
                                    }

                                    if (operationObject.ContainsKey("summary") &&
                                        !string.IsNullOrWhiteSpace(operationObject["summary"]?.ToString()))
                                    {
                                        endpointsWithSummary++;
                                    }

                                    // Check for examples
                                    if (HasExamples(operationObject))
                                    {
                                        endpointsWithExamples++;
                                    }

                                    // Count parameters
                                    if (operationObject.ContainsKey("parameters"))
                                    {
                                        var parameters = operationObject["parameters"];
                                        if (parameters is JArray parametersArray)
                                        {
                                            totalParameters += parametersArray.Count;
                                            parametersWithDescription += parametersArray
                                                .Where(p => p is JObject pObj &&
                                                       pObj.ContainsKey("description") &&
                                                       !string.IsNullOrWhiteSpace(pObj["description"]?.ToString()))
                                                .Count();
                                        }
                                    }

                                    // Count responses
                                    if (operationObject.ContainsKey("responses"))
                                    {
                                        var responses = operationObject["responses"];
                                        if (responses is JObject responsesObject)
                                        {
                                            totalResponseCodes += responsesObject.Count;
                                            responseCodesDocumented += responsesObject.Properties()
                                                .Where(r => r.Value is JObject rObj &&
                                                       rObj.ContainsKey("description") &&
                                                       !string.IsNullOrWhiteSpace(rObj["description"]?.ToString()))
                                                .Count();
                                        }
                                    }
                                }
                            }
                        }
                    }

                    metrics.EndpointsWithDescription = endpointsWithDescription;
                    metrics.EndpointsWithSummary = endpointsWithSummary;
                    metrics.EndpointsWithExamples = endpointsWithExamples;
                    metrics.ParametersWithDescription = parametersWithDescription;
                    metrics.TotalParameters = totalParameters;
                    metrics.ResponseCodesDocumented = responseCodesDocumented;
                    metrics.TotalResponseCodes = totalResponseCodes;

                    // Calculate documentation coverage
                    if (totalEndpoints > 0)
                    {
                        metrics.DocumentationCoverage = (double)endpointsWithDescription / totalEndpoints * 100;
                    }
                }
            }

            // Count schemas with descriptions
            CountSchemaDescriptions(specObject, metrics);

            // Calculate overall quality score
            CalculateQualityScore(metrics);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error analyzing quality metrics");
        }

        return metrics;
    }

    private bool HasExamples(JObject operationObject)
    {
        // Check request body examples
        if (operationObject.ContainsKey("requestBody"))
        {
            var requestBody = operationObject["requestBody"];
            if (requestBody is JObject requestBodyObject && HasContentExamples(requestBodyObject))
            {
                return true;
            }
        }

        // Check response examples
        if (operationObject.ContainsKey("responses"))
        {
            var responses = operationObject["responses"];
            if (responses is JObject responsesObject)
            {
                foreach (var response in responsesObject.Properties())
                {
                    if (response.Value is JObject responseObject && HasContentExamples(responseObject))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private bool HasContentExamples(JObject contentContainer)
    {
        if (contentContainer.ContainsKey("content"))
        {
            var content = contentContainer["content"];
            if (content is JObject contentObject)
            {
                foreach (var mediaType in contentObject.Properties())
                {
                    if (mediaType.Value is JObject mediaTypeObject)
                    {
                        if (mediaTypeObject.ContainsKey("example") || mediaTypeObject.ContainsKey("examples"))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private void CountSchemaDescriptions(JObject specObject, OpenApiQualityMetrics metrics)
    {
        // Count schemas in components (OpenAPI 3.x)
        if (specObject.ContainsKey("components"))
        {
            var components = specObject["components"];
            if (components is JObject componentsObject && componentsObject.ContainsKey("schemas"))
            {
                var schemas = componentsObject["schemas"];
                if (schemas is JObject schemasObject)
                {
                    metrics.TotalSchemas = schemasObject.Count;
                    metrics.SchemasWithDescription = schemasObject.Properties()
                        .Where(s => s.Value is JObject sObj &&
                               sObj.ContainsKey("description") &&
                               !string.IsNullOrWhiteSpace(sObj["description"]?.ToString()))
                        .Count();
                }
            }
        }

        // Count schemas in definitions (Swagger 2.0)
        if (specObject.ContainsKey("definitions"))
        {
            var definitions = specObject["definitions"];
            if (definitions is JObject definitionsObject)
            {
                metrics.TotalSchemas = definitionsObject.Count;
                metrics.SchemasWithDescription = definitionsObject.Properties()
                    .Where(d => d.Value is JObject dObj &&
                           dObj.ContainsKey("description") &&
                           !string.IsNullOrWhiteSpace(dObj["description"]?.ToString()))
                    .Count();
            }
        }
    }

    private void CalculateQualityScore(OpenApiQualityMetrics metrics)
    {
        double score = 0;
        int factors = 0;

        // Documentation coverage (30% weight)
        if (metrics.DocumentationCoverage > 0)
        {
            score += metrics.DocumentationCoverage * 0.3;
            factors++;
        }

        // Parameter documentation (25% weight)
        if (metrics.TotalParameters > 0)
        {
            double parameterScore = (double)metrics.ParametersWithDescription / metrics.TotalParameters * 100;
            score += parameterScore * 0.25;
            factors++;
        }

        // Schema documentation (25% weight)
        if (metrics.TotalSchemas > 0)
        {
            double schemaScore = (double)metrics.SchemasWithDescription / metrics.TotalSchemas * 100;
            score += schemaScore * 0.25;
            factors++;
        }

        // Response documentation (20% weight)
        if (metrics.TotalResponseCodes > 0)
        {
            double responseScore = (double)metrics.ResponseCodesDocumented / metrics.TotalResponseCodes * 100;
            score += responseScore * 0.20;
            factors++;
        }

        // Calculate final score
        metrics.QualityScore = factors > 0 ? score / factors : 0;
    }

    /// <summary>
    /// Generates recommendations based on analysis results
    /// </summary>
    private List<OpenApiRecommendation> GenerateRecommendations(JObject specObject, List<ValidationError> errors)
    {
        var recommendations = new List<OpenApiRecommendation>();

        try
        {
            // Convert errors to recommendations
            foreach (var error in errors.Where(e => e.Severity == "Error"))
            {
                recommendations.Add(new OpenApiRecommendation
                {
                    Type = "Error",
                    Category = "Validation",
                    Priority = "High",
                    Message = error.Message,
                    Path = error.Path,
                    ActionRequired = "Fix this validation error to ensure spec compliance",
                    Impact = "API consumers may not be able to use the specification correctly"
                });
            }

            // Convert warnings to recommendations
            foreach (var error in errors.Where(e => e.Severity == "Warning"))
            {
                recommendations.Add(new OpenApiRecommendation
                {
                    Type = "Warning",
                    Category = "Best Practice",
                    Priority = "Medium",
                    Message = error.Message,
                    Path = error.Path,
                    ActionRequired = "Consider addressing this warning to improve spec quality",
                    Impact = "May affect usability or developer experience"
                });
            }

            // Add quality-based recommendations
            AddQualityRecommendations(specObject, recommendations);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error generating recommendations");
        }

        return recommendations;
    }

    /// <summary>
    /// Represents an endpoint group with collection and parameterized endpoints
    /// </summary>
    private class EndpointGroup
    {
        public string RootPath { get; set; } = string.Empty;
        public List<EndpointInfo> CollectionEndpoints { get; set; } = new();
        public List<EndpointInfo> ParameterizedEndpoints { get; set; } = new();
        public List<EndpointInfo> Endpoints => CollectionEndpoints.Concat(ParameterizedEndpoints).ToList();
    }

    /// <summary>
    /// Represents a single endpoint with its metadata
    /// </summary>
    private class EndpointInfo
    {
        public string Path { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public JObject Operation { get; set; } = new();
        public JObject PathItem { get; set; } = new();
        public bool IsParameterized => Path.Contains('{');
        public string RootPath => GetRootPath(Path);
    }

    private void AddQualityRecommendations(JObject specObject, List<OpenApiRecommendation> recommendations)
    {
        // Check for missing info fields
        if (!specObject.ContainsKey("info") || specObject["info"] is not JObject infoObject)
        {
            return;
        }

        if (!infoObject.ContainsKey("description") || string.IsNullOrWhiteSpace(infoObject["description"]?.ToString()))
        {
            recommendations.Add(new OpenApiRecommendation
            {
                Type = "Improvement",
                Category = "Documentation",
                Priority = "Medium",
                Message = "API description is missing or empty",
                Path = "info.description",
                ActionRequired = "Add a comprehensive description of your API's purpose and functionality",
                Impact = "Helps developers understand the API's capabilities and use cases"
            });
        }

        if (!infoObject.ContainsKey("contact"))
        {
            recommendations.Add(new OpenApiRecommendation
            {
                Type = "Improvement",
                Category = "Documentation",
                Priority = "Low",
                Message = "Contact information is missing",
                Path = "info.contact",
                ActionRequired = "Add contact information for API support",
                Impact = "Helps users get support when needed"
            });
        }

        if (!infoObject.ContainsKey("license"))
        {
            recommendations.Add(new OpenApiRecommendation
            {
                Type = "Improvement",
                Category = "Legal",
                Priority = "Low",
                Message = "License information is missing",
                Path = "info.license",
                ActionRequired = "Add license information for your API",
                Impact = "Clarifies usage rights and restrictions"
            });
        }
    }

    /// <summary>
    /// Groups endpoints by root path and separates collection from parameterized endpoints
    /// </summary>
    private List<EndpointGroup> GroupEndpointsByDependencies(JObject pathsObject, OpenApiValidationOptions options)
    {
        var endpoints = new List<EndpointInfo>();
        var validHttpMethods = new HashSet<string> { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE" };

        // Extract all endpoints
        foreach (var pathProperty in pathsObject.Properties())
        {
            var path = pathProperty.Name;
            var pathItem = pathProperty.Value;

            if (pathItem is JObject pathItemObject)
            {
                foreach (var methodProperty in pathItemObject.Properties())
                {
                    var method = methodProperty.Name.ToUpperInvariant();

                    // Skip non-HTTP method properties like "parameters", "summary", "$ref", "servers", etc.
                    if (!validHttpMethods.Contains(method))
                    {
                        continue;
                    }

                    var operation = methodProperty.Value;
                    if (operation is JObject operationObject)
                    {
                        endpoints.Add(new EndpointInfo
                        {
                            Path = path,
                            Method = method,
                            Operation = operationObject,
                            PathItem = pathItemObject  // Add path item for optional endpoint checking
                        });
                    }
                }
            }
        }

        // Group by root path and separate collection from parameterized
        var groups = endpoints
            .GroupBy(e => e.RootPath)
            .Select(g => new EndpointGroup
            {
                RootPath = g.Key,
                CollectionEndpoints = g.Where(e => !e.IsParameterized && e.Method == "GET").ToList(),
                ParameterizedEndpoints = g.Where(e => e.IsParameterized).ToList()
            })
            .Where(g => g.Endpoints.Any())
            .ToList();

        return groups;
    }

    /// <summary>
    /// Gets the root path from a full path (e.g., /services/{id} -> /services)
    /// </summary>
    private static string GetRootPath(string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
            return "/";

        // Take segments until we hit a parameter
        var rootSegments = new List<string>();
        foreach (var segment in segments)
        {
            if (segment.StartsWith('{') && segment.EndsWith('}'))
                break;
            rootSegments.Add(segment);
        }

        return rootSegments.Any() ? "/" + string.Join("/", rootSegments) : "/";
    }

    /// <summary>
    /// Tests an endpoint and extracts IDs from the response for use by dependent endpoints.
    /// The extractedIds dictionary is updated with any IDs found in the response.
    /// </summary>
    /// <param name="path">The endpoint path to test</param>
    /// <param name="method">The HTTP method to use</param>
    /// <param name="operation">The OpenAPI operation definition</param>
    /// <param name="baseUrl">The base URL for the API</param>
    /// <param name="authentication">Authentication configuration</param>
    /// <param name="options">Validation options</param>
    /// <param name="extractedIds">Dictionary to store extracted IDs (passed by reference, modifications persist)</param>
    /// <param name="semaphore">Semaphore for concurrency control</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The endpoint test result with extracted IDs stored in the shared dictionary</returns>
    private async Task<EndpointTestResult> TestSingleEndpointWithIdExtractionAsync(
        string path, string method, JObject operation, string baseUrl,
        OpenApiValidationOptions options, DataSourceAuthentication? authentication,
        ConcurrentDictionary<string, List<string>> extractedIds, SemaphoreSlim semaphore,
        JObject openApiDocument, string? documentUri, JObject pathItem, CancellationToken cancellationToken)
    {
        var result = await TestSingleEndpointAsync(path, method, operation, baseUrl, options, authentication, semaphore, openApiDocument, documentUri, pathItem, cancellationToken);

        // Extract IDs from successful GET responses for dependency testing
        if (method == "GET" && result.TestResults.Any(r => r.IsSuccess && !string.IsNullOrEmpty(r.ResponseBody)))
        {
            var rootPath = GetRootPath(path);
            var successfulResponse = result.TestResults.First(r => r.IsSuccess);

            _logger.LogInformation("Processing HTTP response from {Url} (Status: {StatusCode}, ResponseSize: {Size} chars)",
                successfulResponse.RequestUrl, successfulResponse.ResponseStatusCode,
                successfulResponse.ResponseBody?.Length ?? 0);

            // Log first 500 characters of response for debugging
            var responsePreview = successfulResponse.ResponseBody!.Length > 500
                ? successfulResponse.ResponseBody[..500] + "..."
                : successfulResponse.ResponseBody;

            _logger.LogDebug("Response content preview: {ResponsePreview}", responsePreview);

            var ids = ExtractIdsFromResponse(successfulResponse.ResponseBody!, rootPath, operation, openApiDocument);

            if (ids.Any())
            {
                // Store extracted IDs in the shared dictionary for use by dependent endpoints
                // Note: ConcurrentDictionary is a reference type, so this modification persists to the caller
                extractedIds[rootPath] = ids;
                _logger.LogInformation("✅ Successfully extracted and stored {Count} IDs from {Path} for root path '{RootPath}': [{Ids}]",
                    ids.Count, path, rootPath, string.Join(", ", ids.Take(3)) + (ids.Count > 3 ? $" and {ids.Count - 3} more..." : ""));

                // Verify the IDs were stored correctly
                if (extractedIds.TryGetValue(rootPath, out var storedIds))
                {
                    _logger.LogDebug("✅ Verified: {Count} IDs successfully stored in extractedIds dictionary for '{RootPath}'",
                        storedIds.Count, rootPath);
                }
                else
                {
                    _logger.LogWarning("⚠️ Warning: IDs extraction appeared successful but verification failed for '{RootPath}'", rootPath);
                }
            }
            else
            {
                _logger.LogWarning("No IDs could be extracted from response for path {Path} (root: {RootPath})", path, rootPath);
            }
        }

        return result;
    }

    /// <summary>
    /// Tests an endpoint with parameter substitution using extracted IDs from the shared dictionary.
    /// This method retrieves IDs extracted by TestSingleEndpointWithIdExtractionAsync and uses them
    /// to test parameterized endpoints with realistic data.
    /// </summary>
    /// <param name="path">The parameterized endpoint path to test</param>
    /// <param name="method">The HTTP method to use</param>
    /// <param name="operation">The OpenAPI operation definition</param>
    /// <param name="baseUrl">The base URL for the API</param>
    /// <param name="authentication">Authentication configuration</param>
    /// <param name="options">Validation options</param>
    /// <param name="extractedIds">Dictionary containing extracted IDs from collection endpoints</param>
    /// <param name="semaphore">Semaphore for concurrency control</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The endpoint test result using extracted IDs for parameters</returns>
    private async Task<EndpointTestResult> TestSingleEndpointWithIdSubstitutionAsync(
        string path, string method, JObject operation, string baseUrl,
        OpenApiValidationOptions options, DataSourceAuthentication? authentication,
        ConcurrentDictionary<string, List<string>> extractedIds, SemaphoreSlim semaphore,
        JObject openApiDocument, string? documentUri, JObject pathItem, CancellationToken cancellationToken)
    {
        var rootPath = GetRootPath(path);

        _logger.LogInformation("🔍 Looking for extracted IDs for root path '{RootPath}'. Available keys in dictionary: [{Keys}]",
            rootPath, string.Join(", ", extractedIds.Keys));

        // Try to retrieve extracted IDs from the shared dictionary populated by collection endpoint tests
        if (extractedIds.TryGetValue(rootPath, out var availableIds) && availableIds.Any())
        {
            _logger.LogInformation("✅ Found {Count} extracted IDs for root path '{RootPath}': [{Ids}]",
                availableIds.Count, rootPath, string.Join(", ", availableIds.Take(3)) + (availableIds.Count > 3 ? "..." : ""));

            // Test up to 10 random IDs from the available IDs
            var random = new Random();
            var idsToTest = availableIds.Count <= 10
                ? availableIds.ToList()
                : availableIds.OrderBy(_ => random.Next()).Take(10).ToList();

            _logger.LogInformation("🎯 Testing {Count} random IDs for endpoint {Path}", idsToTest.Count, path);

            // Create a composite result that combines all test results
            var compositeResult = new EndpointTestResult
            {
                Path = path,
                Method = method,
                Name = operation["name"]?.ToString(),
                OperationId = operation["operationId"]?.ToString(),
                Summary = operation["summary"]?.ToString(),
                IsOptional = operation.IsOptionalEndpoint(),
                Status = "NotTested",
                IsTested = true
            };

            // Test each ID
            var allTestsSuccessful = true;
            foreach (var id in idsToTest)
            {
                var substitutedPath = SubstitutePathParametersWithSpecificId(path, id);
                _logger.LogInformation("Testing with ID '{Id}': {OriginalPath} → {SubstitutedPath}", id, path, substitutedPath);

                var singleResult = await TestSingleEndpointAsync(substitutedPath, method, operation, baseUrl, options, authentication, semaphore, openApiDocument, documentUri, pathItem, cancellationToken, testedId: id);

                // Aggregate the results
                compositeResult.TestResults.AddRange(singleResult.TestResults);
                //compositeResult.ValidationErrors.AddRange(singleResult.ValidationErrors);
                //compositeResult.SchemaValidationDetails.AddRange(singleResult.SchemaValidationDetails);

                if (singleResult.Status == "Failed" || singleResult.Status == "Error")
                {
                    allTestsSuccessful = false;
                }
            }

            // Set the composite status based on all test results
            if (compositeResult.TestResults.Any())
            {
                if (allTestsSuccessful)
                {
                    compositeResult.Status = "Success";
                }
                else if (compositeResult.TestResults.Any(tr => tr.ValidationResult != null && tr.ValidationResult.Errors.Any(e => e.Severity == "Warning")) && !compositeResult.TestResults.Any(tr => tr.ValidationResult != null && tr.ValidationResult.Errors.Any(e => e.Severity == "Error")))
                {
                    compositeResult.Status = "Warning";
                }
                else
                {
                    compositeResult.Status = "Failed";
                }
            }

            return compositeResult;
        }
        else
        {
            _logger.LogWarning("⚠️ No extracted IDs available for root path '{RootPath}'. Dictionary contains {KeyCount} entries. Marking endpoint as NotTested: {Path}",
                rootPath, extractedIds.Count, path);

            // Log available keys for debugging
            if (extractedIds.Any())
            {
                _logger.LogDebug("Available ID keys in dictionary: [{Keys}]", string.Join(", ", extractedIds.Keys));
            }

            // Return a NotTested result instead of falling back to default values
            return new EndpointTestResult
            {
                Path = path,
                Method = method,
                Name = operation["name"]?.ToString(),
                OperationId = operation["operationId"]?.ToString(),
                Summary = operation["summary"]?.ToString(),
                IsOptional = operation.IsOptionalEndpoint(),
                Status = "NotTested",
                IsTested = false,
                TestResults = new List<HttpTestResult>(){
                    new() {
                        IsSuccess = false,
                        RequestUrl = $"{baseUrl}{path}",
                        ErrorMessage = "No extracted IDs available for parameter substitution. Endpoint was not tested.",
                        ValidationResult= new ValidationResult
                        {
                            IsValid = false,
                            Errors = new List<ValidationError>
                            {
                                new ValidationError
                                {
                                    Path = path,
                                    Message = "No extracted IDs available for parameter substitution. Endpoint was not tested.",
                                    ErrorCode = "NO_IDS_AVAILABLE",
                                    Severity = "Warning"
                                }
                            }
                        }
                    }
                }
            };
        }
    }

    /// <summary>
    /// Extracts IDs from a JSON response using OpenAPI schema information to identify ID field locations
    /// </summary>
    private List<string> ExtractIdsFromResponse(string responseBody, string rootPath, JObject operation, JObject openApiDocument)
    {
        var ids = new List<string>();

        _logger.LogInformation("Starting ID extraction from JSON response for root path: {RootPath}", rootPath);

        // First, try to extract ID field names from the OpenAPI schema
        var schemaIdFields = ExtractIdFieldsFromSchema(operation, openApiDocument);
        if (schemaIdFields.Any())
        {
            _logger.LogDebug("Found ID fields from OpenAPI schema: [{IdFields}]", string.Join(", ", schemaIdFields));
        }
        else
        {
            _logger.LogDebug("No ID fields identified from OpenAPI schema, falling back to common field names");
        }

        try
        {
            var json = JToken.Parse(responseBody);
            _logger.LogDebug("Parsed JSON type: {JsonType}", json.Type);

            // Handle array responses (most common for collections)
            if (json is JArray array)
            {
                _logger.LogInformation("Found JSON array with {Count} items, extracting all IDs", array.Count);

                foreach (var item in array)
                {
                    var id = ExtractIdFromObject(item, schemaIdFields);
                    if (!string.IsNullOrEmpty(id))
                    {
                        _logger.LogDebug("Found ID in array item: {Id}", id);
                        ids.Add(id);
                    }
                }
            }
            // Handle object responses with data/items property
            else if (json is JObject obj)
            {
                // First try to identify collection properties from the schema
                var collectionProps = ExtractCollectionPropertiesFromSchema(operation, openApiDocument);
                if (collectionProps.Any())
                {
                    _logger.LogDebug("Found collection properties from OpenAPI schema: [{CollectionProps}]", string.Join(", ", collectionProps));

                    foreach (var propName in collectionProps)
                    {
                        if (obj[propName] is JArray items)
                        {
                            _logger.LogDebug("Processing collection property '{PropName}' with {Count} items", propName, items.Count);
                            foreach (var item in items)
                            {
                                var id = ExtractIdFromObject(item, schemaIdFields);
                                if (!string.IsNullOrEmpty(id))
                                    ids.Add(id);
                            }
                            break;
                        }
                    }
                }

                // If no schema-based collection found, try common collection property names
                if (!ids.Any())
                {
                    foreach (var propName in new[] { "data", "items", "results", "content", "contents" })
                    {
                        if (obj[propName] is JArray items)
                        {
                            _logger.LogDebug("Processing fallback collection property '{PropName}' with {Count} items", propName, items.Count);
                            foreach (var item in items)
                            {
                                var id = ExtractIdFromObject(item, schemaIdFields);
                                if (!string.IsNullOrEmpty(id))
                                    ids.Add(id);
                            }
                            break;
                        }
                    }
                }

                // If no collection found, try to extract ID from the object itself
                if (!ids.Any())
                {
                    var id = ExtractIdFromObject(json, schemaIdFields);
                    if (!string.IsNullOrEmpty(id))
                        ids.Add(id);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to extract IDs from response for path {Path}", rootPath);
        }

        return ids.Distinct().ToList();
    }

    /// <summary>
    /// Extracts an ID from a JSON object using OpenAPI schema-identified ID fields, with fallback to common names
    /// </summary>
    private static string? ExtractIdFromObject(JToken item, List<string> schemaIdFields)
    {
        if (item is not JObject obj)
            return null;

        // First try fields identified from the OpenAPI schema
        foreach (var idField in schemaIdFields)
        {
            var idValue = obj[idField]?.ToString();
            if (!string.IsNullOrWhiteSpace(idValue))
                return idValue;
        }

        // Fallback to common ID field names if schema-based extraction failed
        foreach (var idField in new[] { "id", "_id", "uid", "uuid", "identifier", "key" })
        {
            var idValue = obj[idField]?.ToString();
            if (!string.IsNullOrWhiteSpace(idValue))
                return idValue;
        }

        return null;
    }

    /// <summary>
    /// Extracts ID field names from the OpenAPI response schema
    /// </summary>
    private List<string> ExtractIdFieldsFromSchema(JObject operation, JObject openApiDocument)
    {
        var idFields = new List<string>();

        try
        {
            // Get the 200 response schema
            var responseSchema = operation["responses"]?["200"]?["content"]?["application/json"]?["schema"];
            if (responseSchema != null)
            {
                ExtractIdFieldsFromSchemaRecursive(responseSchema, idFields);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract ID fields from OpenAPI schema");
        }

        return idFields.Distinct().ToList();
    }

    /// <summary>
    /// Extracts collection property names from the OpenAPI response schema
    /// </summary>
    private List<string> ExtractCollectionPropertiesFromSchema(JObject operation, JObject openApiDocument)
    {
        var collectionProps = new List<string>();

        try
        {
            // Get the 200 response schema
            var responseSchema = operation["responses"]?["200"]?["content"]?["application/json"]?["schema"];
            if (responseSchema != null)
            {
                ExtractCollectionPropertiesFromSchemaRecursive(responseSchema, collectionProps);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to extract collection properties from OpenAPI schema");
        }

        return collectionProps.Distinct().ToList();
    }

    /// <summary>
    /// Recursively extracts ID field names from a schema structure
    /// </summary>
    private static void ExtractIdFieldsFromSchemaRecursive(JToken schema, List<string> idFields)
    {
        if (schema is JObject schemaObj)
        {
            // Check if this schema has properties
            if (schemaObj["properties"] is JObject properties)
            {
                foreach (var prop in properties.Properties())
                {
                    var propName = prop.Name;
                    var propSchema = prop.Value;

                    // Check if this looks like an ID field
                    if (IsIdField(propName, propSchema))
                    {
                        idFields.Add(propName);
                    }

                    // Recursively check nested properties
                    ExtractIdFieldsFromSchemaRecursive(propSchema, idFields);
                }
            }

            // Check array items
            if (schemaObj["items"] is JToken itemsSchema)
            {
                ExtractIdFieldsFromSchemaRecursive(itemsSchema, idFields);
            }

            // Check allOf, anyOf, oneOf
            foreach (var combiner in new[] { "allOf", "anyOf", "oneOf" })
            {
                if (schemaObj[combiner] is JArray combinerArray)
                {
                    foreach (var item in combinerArray)
                    {
                        ExtractIdFieldsFromSchemaRecursive(item, idFields);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Recursively extracts collection property names from a schema structure
    /// </summary>
    private static void ExtractCollectionPropertiesFromSchemaRecursive(JToken schema, List<string> collectionProps)
    {
        if (schema is JObject schemaObj)
        {
            // Check if this schema has properties
            if (schemaObj["properties"] is JObject properties)
            {
                foreach (var prop in properties.Properties())
                {
                    var propName = prop.Name;
                    var propSchema = prop.Value;

                    // Check if this property is an array (collection)
                    if (propSchema is JObject propObj && propObj["type"]?.ToString() == "array")
                    {
                        collectionProps.Add(propName);
                    }

                    // Recursively check nested properties
                    ExtractCollectionPropertiesFromSchemaRecursive(propSchema, collectionProps);
                }
            }

            // Check allOf, anyOf, oneOf
            foreach (var combiner in new[] { "allOf", "anyOf", "oneOf" })
            {
                if (schemaObj[combiner] is JArray combinerArray)
                {
                    foreach (var item in combinerArray)
                    {
                        ExtractCollectionPropertiesFromSchemaRecursive(item, collectionProps);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Determines if a property name and schema indicate an ID field
    /// </summary>
    private static bool IsIdField(string propName, JToken? propSchema)
    {
        // Check property name patterns
        var nameLower = propName.ToLowerInvariant();
        if (nameLower == "id" || nameLower == "_id" || nameLower == "uid" ||
            nameLower == "uuid" || nameLower == "identifier" || nameLower == "key" ||
            nameLower.EndsWith("id") || nameLower.EndsWith("_id"))
        {
            return true;
        }

        // Check schema properties for ID indicators
        if (propSchema is JObject schemaObj)
        {
            var description = schemaObj["description"]?.ToString().ToLowerInvariant();
            if (!string.IsNullOrEmpty(description) &&
                (description.Contains("identifier") || description.Contains("unique id") || description.Contains(" id ")))
            {
                return true;
            }

            var format = schemaObj["format"]?.ToString().ToLowerInvariant();
            if (format == "uuid" || format == "guid")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Helper method to extract a schema from a given path in the OpenAPI document
    /// This is used by parameter resolution to resolve parameter references
    /// </summary>
    private static JToken? GetSchemaFromPath(JObject document, string path)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        JToken? current = document;

        foreach (var part in parts)
        {
            if (current is JObject obj && obj.ContainsKey(part))
            {
                current = obj[part];
            }
            else if (current is JArray array && int.TryParse(part, out var index) && index >= 0 && index < array.Count)
            {
                current = array[index];
            }
            else
            {
                return null; // Path not found
            }
        }

        return current;
    }

    /// <summary>
    /// Substitutes path parameters with a specific ID value
    /// </summary>
    private string SubstitutePathParametersWithSpecificId(string path, string id)
    {
        var substitutedPath = path;

        // Find all path parameters and replace with the specific ID
        var matches = Regex.Matches(path, @"\{([^}]+)\}");

        foreach (Match match in matches)
        {
            var paramPlaceholder = match.Value;
            substitutedPath = substitutedPath.Replace(paramPlaceholder, id);
        }

        return substitutedPath;
    }

    /// <summary>
    /// Applies authentication to an HTTP request based on the provided authentication configuration
    /// Supports API key, bearer token, basic authentication, and custom headers
    /// </summary>
    /// <param name="request">The HTTP request message to apply authentication to</param>
    /// <param name="authentication">The authentication configuration containing credentials and auth type</param>
    private void ApplyAuthenticationHeaders(HttpRequestMessage request, DataSourceAuthentication authentication)
    {
        // Apply API Key authentication
        if (!string.IsNullOrEmpty(authentication.ApiKey))
        {
            var headerName = string.IsNullOrEmpty(authentication.ApiKeyHeader) ? "X-API-Key" : authentication.ApiKeyHeader;
            request.Headers.Add(headerName, authentication.ApiKey);
            _logger.LogDebug("Applied API Key authentication with header: {HeaderName}", headerName);
        }

        // Apply Bearer Token authentication
        if (!string.IsNullOrEmpty(authentication.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authentication.BearerToken);
            _logger.LogDebug("Applied Bearer Token authentication");
        }

        // Apply Basic Authentication
        if (authentication.BasicAuth != null && 
            !string.IsNullOrEmpty(authentication.BasicAuth.Username))
        {
            var credentials = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{authentication.BasicAuth.Username}:{authentication.BasicAuth.Password ?? string.Empty}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            _logger.LogDebug("Applied Basic authentication for user: {Username}", authentication.BasicAuth.Username);
        }

        // Apply Custom Headers
        if (authentication.CustomHeaders != null && authentication.CustomHeaders.Any())
        {
            foreach (var header in authentication.CustomHeaders)
            {
                if (!string.IsNullOrEmpty(header.Key) && !string.IsNullOrEmpty(header.Value))
                {
                    request.Headers.Add(header.Key, header.Value);
                    _logger.LogDebug("Applied custom header: {HeaderName}", header.Key);
                }
            }
        }
    }
}

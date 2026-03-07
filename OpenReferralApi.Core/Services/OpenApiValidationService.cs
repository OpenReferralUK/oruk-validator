using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    private static readonly Regex ArrayIndexRegex = new(@"\[[^\]]*\]", RegexOptions.Compiled);

    private readonly ILogger<OpenApiValidationService> _logger;
    private readonly HttpClient _httpClient;
    private readonly IJsonValidatorService _jsonValidatorService;
    private readonly ISchemaResolverService _schemaResolverService;
    private readonly IOpenApiDiscoveryService _discoveryService;
    private readonly OpenApiSpecFetcher _specFetcher;
    private readonly bool _allowUserSuppliedAuth;

    public OpenApiValidationService(
        ILogger<OpenApiValidationService> logger,
        HttpClient httpClient,
        IJsonValidatorService jsonValidatorService,
        ISchemaResolverService schemaResolverService,
        IOpenApiDiscoveryService discoveryService,
        IOptions<AuthenticationOptions> authOptions)
    {
        _logger = logger;
        _httpClient = httpClient;
        _jsonValidatorService = jsonValidatorService;
        _schemaResolverService = schemaResolverService;
        _discoveryService = discoveryService;
        _allowUserSuppliedAuth = authOptions.Value.AllowUserSuppliedAuth;
        _specFetcher = new OpenApiSpecFetcher(httpClient, logger, schemaResolverService, allowUserSuppliedAuth: _allowUserSuppliedAuth);
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
                        _logger.LogInformation("Discovered OpenAPI schema URL: {Url} (Reason: {Reason})", SchemaResolverService.SanitizeUrlForLogging(discoveredUrl), reason);
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
            bool isResolved = false;

            // User-supplied authentication for schema and datasource requests is feature-gated
            // and must pass strict validation before it can be applied.
            var schemaRequestAuth = TryGetValidatedRequestAuthentication("schema", request.OpenApiSchema?.Authentication);
            var dataSourceRequestAuth = TryGetValidatedRequestAuthentication("datasource", request.DataSourceAuth);

            if (!string.IsNullOrEmpty(request.OpenApiSchema?.Url))
            {
                // Fetch OpenAPI spec but defer resolution until we know we need it
                // This avoids expensive resolution when we're only validating spec structure
                // or when most endpoints won't be tested
                openApiSpec = await _specFetcher.FetchOpenApiSpecFromUrlAsync(
                    request.OpenApiSchema.Url,
                    schemaRequestAuth,
                    cancellationToken,
                    resolveReferences: false);
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
                // Resolve references now that we know we're actually testing endpoints
                // This lazy approach avoids wasting resolution work when endpoints aren't tested
                if (!isResolved)
                {
                    _logger.LogDebug("Resolving OpenAPI document references for endpoint testing");
                    var resolvedContent = await _schemaResolverService.ResolveAsync(openApiSpec.ToString(), request.OpenApiSchema?.Url, schemaRequestAuth);
                    openApiSpec = JObject.Parse(resolvedContent);
                    isResolved = true;
                }

                endpointTests = await TestEndpointsAsync(openApiSpec, request.BaseUrl, request.Options, dataSourceRequestAuth, request.OpenApiSchema?.Url, cancellationToken);
                result.EndpointTests = endpointTests;
            }

            // Build summary
            result.Summary = BuildTestSummary(specValidation, endpointTests, request.Options);
            result.IsValid = (specValidation?.IsValid ?? true) && result.Summary.FailedTests == 0;

            // Set metadata
            result.Metadata = new CommonValidationMetadata
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
                    ep.RefreshFlattenedFields();
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
                Message = $"Validation error: {SanitizeExceptionMessage(ex.Message)}",
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
                if (schemaValidation.Errors.Any())
                {
                    errors.AddRange(schemaValidation.Errors);
                }

                // Log which schema was used for validation
                var dialectInfo = specObject.ContainsKey("jsonSchemaDialect")
                    ? $"using jsonSchemaDialect: {SchemaResolverService.SanitizeStringForLogging(specObject["jsonSchemaDialect"]?.ToString() ?? string.Empty)}"
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
                Message = $"Could not validate against OpenAPI schema: {SanitizeExceptionMessage(ex.Message)}",
                ErrorCode = "SCHEMA_VALIDATION_FAILED",
                Severity = "Warning"
            });
        }

        validation.Errors = NormalizeAndDeduplicateValidationErrors(errors);
        validation.IsValid = !validation.Errors.Any();

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
                _logger.LogInformation("Testing endpoint group: {GroupName} with {Count} endpoints", SanitizeForLogging(group.RootPath), group.Endpoints.Count);

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
                    SanitizeForLogging(group.RootPath), group.CollectionEndpoints.Count, group.ParameterizedEndpoints.Count);
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
            Status = EndpointTestStatus.NotTested
        };

        try
        {
            bool isOptional = operation.IsOptionalEndpoint();
            bool skipOptional = options.TestOptionalEndpoints == false && isOptional;
            if (skipOptional)
            {
                result.Status = EndpointTestStatus.Skipped;
                return result;
            }

            // Check if this endpoint has pagination support
            _logger.LogDebug("Checking pagination support for {Method} {Path}", SchemaResolverService.SanitizeStringForLogging(method), SchemaResolverService.SanitizeStringForLogging(path));
            bool hasPagination = method == "GET" && HasPageParameter(resolvedParams);
            _logger.LogInformation("{Method} {Path}: hasPagination={HasPagination}", SchemaResolverService.SanitizeStringForLogging(method), SchemaResolverService.SanitizeStringForLogging(path), hasPagination);

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
                if (!testResult.IsSuccessStatusCode)
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
                        result.Status = EndpointTestStatus.PassedWithWarnings;
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
                        result.Status = EndpointTestStatus.FailedValidation;
                    }
                }

                // Validate response if schema is defined
                if (testResult.IsSuccessStatusCode && testResult.ResponseBody != null)
                {
                    await ValidateResponseAsync(testResult, operation, openApiDocument, documentUri, options, cancellationToken);
                    // If no schema is defined (ValidationResult has no errors and IsValid is false), treat as passed
                    // A schema validation that failed would have errors, while a successful validation would have IsValid=true
                    var hasValidationErrors = testResult.ValidationResult != null && 
                                             testResult.ValidationResult.Errors.Any();
                    var isValidationSuccess = testResult.ValidationResult != null && 
                                             testResult.ValidationResult.IsValid;
                    
                    result.Status = (!hasValidationErrors && !isValidationSuccess) || isValidationSuccess
                        ? EndpointTestStatus.PassedValidation
                        : EndpointTestStatus.FailedValidation;
                }


                // Optional endpoint warning logic (only apply if status wasn't already set by non-success handling)
                if (result.Status == EndpointTestStatus.NotTested || result.Status == EndpointTestStatus.PassedValidation || result.Status == EndpointTestStatus.FailedValidation)
                {
                    if (isOptional && options.TestOptionalEndpoints && options.TreatOptionalEndpointsAsWarnings)
                    {
                        // If there are validation errors, report as warnings
                        if (testResult.ValidationResult != null && !testResult.ValidationResult.IsValid)
                        {
                            result.Status = EndpointTestStatus.PassedWithWarnings;
                        }
                        else if (result.Status != EndpointTestStatus.PassedWithWarnings)
                        {
                            result.Status = testResult.IsSuccessStatusCode
                                ? EndpointTestStatus.PassedValidation
                                : EndpointTestStatus.PassedWithWarnings;
                        }
                    }
                    else if (result.Status != EndpointTestStatus.PassedWithWarnings && result.Status != EndpointTestStatus.FailedValidation)
                    {
                        result.Status = testResult.IsSuccessStatusCode
                            ? EndpointTestStatus.PassedValidation
                            : EndpointTestStatus.FailedValidation;
                    }
                }

                NormalizeValidationResultErrors(testResult.ValidationResult);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error testing endpoint {Method} {Path}", SchemaResolverService.SanitizeStringForLogging(method), SchemaResolverService.SanitizeStringForLogging(path));
            result.TestResults.Add(new HttpTestResult
            {
                RequestUrl = $"{baseUrl}{path}",
                RequestMethod = method,
                IsSuccessStatusCode = false,
                ErrorMessage = SanitizeExceptionMessage(ex.Message),
                ResponseTime = TimeSpan.Zero
            });
            result.Status = EndpointTestStatus.Error;
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
        _logger.LogInformation("Testing paginated endpoint: {Method} {Path}", SchemaResolverService.SanitizeStringForLogging(method), SchemaResolverService.SanitizeStringForLogging(path));

        result.IsTested = true;

        // Test first page (page=1)
        _logger.LogDebug("Testing first page for {Path}", SanitizeForLogging(path));
        var firstPageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: 1);
        var firstPageResult = await ExecuteHttpRequestAsync(firstPageUrl, method, operation, options, auth, cancellationToken);
        result.TestResults.Add(firstPageResult);

        if (!firstPageResult.IsSuccessStatusCode)
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
                NormalizeValidationResultErrors(firstPageResult.ValidationResult);
                result.Status = EndpointTestStatus.PassedWithWarnings;
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
                NormalizeValidationResultErrors(firstPageResult.ValidationResult);
                result.Status = EndpointTestStatus.FailedValidation;
            }
            return;
        }

        // Validate first page response schema
        if (firstPageResult.ResponseBody != null)
        {
            await ValidateResponseAsync(firstPageResult, operation, openApiDocument, documentUri, options, cancellationToken);
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
            NormalizeValidationResultErrors(firstPageResult.ValidationResult);
            firstPageResult.ValidationResult.IsValid = false;
            result.Status = EndpointTestStatus.PassedWithWarnings;
            _logger.LogWarning("Paginated endpoint {Path} returned empty feed (0 items)", SanitizeForLogging(path));
            return; // No further pagination testing needed for empty feeds
        }

        if (paginationInfo.TotalPages.HasValue && paginationInfo.TotalPages.Value > 1)
        {
            var totalPages = paginationInfo.TotalPages.Value;
            _logger.LogInformation("Endpoint {Path} has {TotalPages} pages, testing pagination", SanitizeForLogging(path), totalPages);

            // Test middle page if there are more than 2 pages
            if (totalPages > 2)
            {
                var middlePage = totalPages / 2;
                _logger.LogDebug("Testing middle page {PageNumber} for {Path}", middlePage, SanitizeForLogging(path));
                var middlePageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: middlePage);
                var middlePageResult = await ExecuteHttpRequestAsync(middlePageUrl, method, operation, options, auth, cancellationToken);
                result.TestResults.Add(middlePageResult);

                if (middlePageResult.IsSuccessStatusCode && middlePageResult.ResponseBody != null)
                {
                    await ValidateResponseAsync(middlePageResult, operation, openApiDocument, documentUri, options, cancellationToken);
                }
            }

            // Test last page
            _logger.LogDebug("Testing last page {PageNumber} for {Path}", totalPages, SanitizeForLogging(path));
            var lastPageUrl = BuildFullUrl(baseUrl, path, resolvedParams, options, pageNumber: totalPages);
            var lastPageResult = await ExecuteHttpRequestAsync(lastPageUrl, method, operation, options, auth, cancellationToken);
            result.TestResults.Add(lastPageResult);

            if (lastPageResult.IsSuccessStatusCode && lastPageResult.ResponseBody != null)
            {
                await ValidateResponseAsync(lastPageResult, operation, openApiDocument, documentUri, options, cancellationToken);
            }
        }
        else
        {
            _logger.LogDebug("Endpoint {Path} has only 1 page or pagination info not available, skipping additional page tests", SanitizeForLogging(path));
        }

        foreach (var testResult in result.TestResults)
        {
            NormalizeValidationResultErrors(testResult.ValidationResult);
        }

        result.Status = DeterminePaginatedEndpointStatus(result);
    }

    private static EndpointTestStatus DeterminePaginatedEndpointStatus(EndpointTestResult result)
    {
        if (!result.TestResults.Any())
        {
            return EndpointTestStatus.NotTested;
        }

        if (result.TestResults.Any(tr => !tr.IsSuccessStatusCode))
        {
            return result.IsOptional
                ? EndpointTestStatus.PassedWithWarnings
                : EndpointTestStatus.FailedValidation;
        }

        var validationErrors = result.TestResults
            .Where(tr => tr.ValidationResult != null)
            .SelectMany(tr => tr.ValidationResult!.Errors);

        if (validationErrors.Any(e => string.Equals(e.Severity, "Error", StringComparison.OrdinalIgnoreCase)))
        {
            return EndpointTestStatus.FailedValidation;
        }

        if (validationErrors.Any(e => string.Equals(e.Severity, "Warning", StringComparison.OrdinalIgnoreCase)))
        {
            return EndpointTestStatus.PassedWithWarnings;
        }

        if (result.TestResults.Any(tr => tr.ValidationResult != null && !tr.ValidationResult.IsValid))
        {
            return EndpointTestStatus.FailedValidation;
        }

        return EndpointTestStatus.PassedValidation;
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
                _logger.LogDebug("Checking param: name={Name}, in={In}", SchemaResolverService.SanitizeStringForLogging(name ?? string.Empty), SchemaResolverService.SanitizeStringForLogging(inLocation ?? string.Empty));

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
                if (param is JObject paramObj)
                {
                    var paramName = paramObj["name"]?.ToString();
                    _logger.LogDebug("Path-level param: {Name}", SchemaResolverService.SanitizeStringForLogging(paramName ?? string.Empty));
                }
            }
        }

        // Add operation-level parameters (these can override path-level params)
        if (operation["parameters"] is JArray operationParams)
        {
            _logger.LogDebug("Found {Count} operation-level parameters", operationParams.Count);
            foreach (var param in operationParams)
            {
                resolvedParams.Add(param);
                if (param is JObject paramObj)
                {
                    var paramName = paramObj["name"]?.ToString();
                    _logger.LogDebug("Operation-level param: {Name}", SchemaResolverService.SanitizeStringForLogging(paramName ?? string.Empty));
                }
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

            // Apply request-supplied authentication only for HTTPS endpoints.
            // Never send user-provided credentials over plain HTTP.
            if (authentication != null &&
                Uri.TryCreate(url, UriKind.Absolute, out var requestUri) &&
                string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                ApplyAuthenticationHeaders(request, authentication);
            }
            else if (authentication != null)
            {
                _logger.LogWarning(
                    "User-supplied data source authentication was provided for a non-HTTPS endpoint. Skipping auth headers for {Url}",
                    SanitizeForLogging(url));
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
            testResult.IsSuccessStatusCode = response.IsSuccessStatusCode;
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
            testResult.IsSuccessStatusCode = false;
            testResult.ErrorMessage = SanitizeExceptionMessage(ex.Message);
        }

        return testResult;
    }

    private async Task ValidateResponseAsync(HttpTestResult testResult, JObject operation, JObject openApiDocument, string? documentUri, OpenApiValidationOptions options, CancellationToken cancellationToken)
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
                                    _logger.LogDebug("validating against schema (length: {Length} chars)", schemaJson.Length);
                                    // Schema is extracted from the already-resolved OpenAPI document
                                    // All $ref references were resolved when fetching the OpenAPI spec
                                    // JsonValidatorService will create a JSchema from this resolved schema
                                    var validationRequest = new ValidationRequest
                                    {
                                        JsonData = JsonConvert.DeserializeObject(testResult.ResponseBody ?? "{}"),
                                        Schema = schema,
                                        Options = new ValidationOptions
                                        {
                                            ReportAdditionalFields = options?.ReportAdditionalFields ?? false
                                        }
                                    };
                                    var validationResult = await _jsonValidatorService.ValidateAsync(validationRequest, cancellationToken);
                                    testResult.ValidationResult = validationResult;
                                    NormalizeValidationResultErrors(testResult.ValidationResult);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not validate response for {Url}", SchemaResolverService.SanitizeUrlForLogging(testResult.RequestUrl ?? string.Empty));
        }
    }

    private static void NormalizeValidationResultErrors(ValidationResult? validationResult)
    {
        if (validationResult?.Errors == null || validationResult.Errors.Count == 0)
        {
            return;
        }

        validationResult.Errors = NormalizeAndDeduplicateValidationErrors(validationResult.Errors);
    }

    private static List<ValidationError> NormalizeAndDeduplicateValidationErrors(IEnumerable<ValidationError> errors)
    {
        var capacity = errors is ICollection<ValidationError> collection ? collection.Count : 0;
        var seenPaths = capacity > 0
            ? new HashSet<string>(capacity, StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);
        var deduplicatedErrors = capacity > 0
            ? new List<ValidationError>(capacity)
            : new List<ValidationError>();

        foreach (var error in errors)
        {
            var normalizedPath = NormalizeValidationErrorText(error.Path);

            // Keep the first validation error encountered for each normalized path.
            if (!seenPaths.Add(normalizedPath))
            {
                continue;
            }

            // Normalize message only for kept entries to avoid work for discarded duplicates.
            deduplicatedErrors.Add(new ValidationError
            {
                Path = normalizedPath,
                Message = NormalizeValidationErrorText(error.Message),
                ErrorCode = error.ErrorCode,
                Severity = error.Severity,
                LineNumber = error.LineNumber,
                ColumnNumber = error.ColumnNumber
            });
        }

        return deduplicatedErrors;
    }

    private static string NormalizeValidationErrorText(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        if (input.IndexOf('[') < 0)
        {
            return input;
        }

        return ArrayIndexRegex.Replace(input, string.Empty);
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
                Message = $"Invalid JSON format: {SanitizeExceptionMessage(ex.Message)}",
                ErrorCode = "INVALID_JSON",
                Severity = "Error"
            });
        }
        catch (Exception ex)
        {
            errors.Add(new ValidationError
            {
                Path = "",
                Message = $"Schema validation error: {SanitizeExceptionMessage(ex.Message)}",
                ErrorCode = "SCHEMA_VALIDATION_ERROR",
                Severity = "Error"
            });
        }

        return errors;
    }

    /// <summary>
    /// Sanitizes exception messages to prevent log injection attacks by removing control characters.
    /// </summary>
    private static string SanitizeExceptionMessage(string message)
    {
        if (string.IsNullOrEmpty(message))
            return string.Empty;

        // Remove control characters (including CR/LF) to prevent log forging
        var sanitized = new string(message.Where(c => !char.IsControl(c)).ToArray());

        // Limit length to prevent log flooding
        const int maxLength = 500;
        if (sanitized.Length > maxLength)
        {
            sanitized = sanitized.Substring(0, maxLength) + "...(truncated)";
        }

        return sanitized;
    }

    private DataSourceAuthentication? TryGetValidatedRequestAuthentication(string context, DataSourceAuthentication? auth)
    {
        // Evaluate the server-side feature gate first so user-controlled request content
        // cannot influence whether the authorization policy check is reached.
        if (!_allowUserSuppliedAuth)
        {
            if (auth != null)
            {
                _logger.LogWarning(
                    "User-supplied authentication was provided for {Context} but is disabled by server configuration",
                    SanitizeForLogging(context));
            }

            return null;
        }

        if (auth == null)
        {
            return null;
        }

        var validated = ValidateAuthentication(auth);
        if (validated == null)
        {
            _logger.LogWarning(
                "Rejected invalid user-supplied authentication for {Context}",
                SanitizeForLogging(context));
        }

        return validated;
    }

    private static DataSourceAuthentication? ValidateAuthentication(DataSourceAuthentication? auth)
    {
        if (auth == null)
        {
            return null;
        }

        const int maxTokenLength = 4096;

        static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        static bool IsTooLong(string? value, int maxLength) => !string.IsNullOrEmpty(value) && value.Length > maxLength;

        // Perform stricter validation on the authentication configuration.
        // If it fails validation, treat it as if no authentication was provided.
        var apiKey = Normalize(auth.ApiKey);
        var apiKeyHeader = Normalize(auth.ApiKeyHeader) ?? "X-API-Key";
        var bearerToken = Normalize(auth.BearerToken);
        var basicUsername = Normalize(auth.BasicAuth?.Username);
        var basicPassword = Normalize(auth.BasicAuth?.Password);

        if (IsTooLong(apiKey, maxTokenLength) ||
            IsTooLong(bearerToken, maxTokenLength) ||
            IsTooLong(basicUsername, maxTokenLength) ||
            IsTooLong(basicPassword, maxTokenLength))
        {
            return null;
        }

        var hasApiKey = !string.IsNullOrEmpty(apiKey);
        if (hasApiKey && !IsValidHttpHeaderName(apiKeyHeader))
        {
            return null;
        }

        var hasBearer = !string.IsNullOrEmpty(bearerToken);
        var hasBasic = auth.BasicAuth != null
                       && !string.IsNullOrEmpty(basicUsername)
                       && !string.IsNullOrEmpty(basicPassword);
        var hasCustomHeaders = auth.CustomHeaders != null && auth.CustomHeaders.Count > 0;

        var mechanismsCount = 0;
        if (hasApiKey) mechanismsCount++;
        if (hasBearer) mechanismsCount++;
        if (hasBasic) mechanismsCount++;
        if (hasCustomHeaders) mechanismsCount++;

        // Require at least one and at most one primary authentication mechanism.
        if (mechanismsCount != 1)
        {
            return null;
        }

        // Return a sanitized copy so that downstream code does not operate on the original user object.
        var validated = new DataSourceAuthentication();

        if (hasApiKey)
        {
            validated.ApiKey = apiKey;
            validated.ApiKeyHeader = apiKeyHeader;
        }
        else if (hasBearer)
        {
            validated.BearerToken = bearerToken;
        }
        else if (hasBasic)
        {
            validated.BasicAuth = new BasicAuthentication
            {
                Username = basicUsername!,
                Password = basicPassword!
            };
        }
        else if (hasCustomHeaders)
        {
            // Copy only non-empty header names and values that pass header safety checks.
            validated.CustomHeaders = new Dictionary<string, string>();
            foreach (var kvp in auth.CustomHeaders!)
            {
                var headerName = Normalize(kvp.Key);
                var headerValue = Normalize(kvp.Value);

                if (string.IsNullOrEmpty(headerName) ||
                    string.IsNullOrEmpty(headerValue) ||
                    !IsValidHttpHeaderName(headerName) ||
                    !IsSafeHeaderValue(headerValue) ||
                    IsTooLong(headerValue, maxTokenLength))
                {
                    return null;
                }

                validated.CustomHeaders[headerName] = headerValue;
            }

            if (validated.CustomHeaders.Count == 0)
            {
                return null;
            }

            if (validated.CustomHeaders.Count > 20)
            {
                return null;
            }
        }

        // Ensure all outgoing header values are safe against CRLF/control character injection.
        if ((validated.ApiKey != null && !IsSafeHeaderValue(validated.ApiKey)) ||
            (validated.BearerToken != null && !IsSafeHeaderValue(validated.BearerToken)) ||
            (validated.BasicAuth?.Username != null && !IsSafeHeaderValue(validated.BasicAuth.Username)) ||
            (validated.BasicAuth?.Password != null && !IsSafeHeaderValue(validated.BasicAuth.Password)))
        {
            return null;
        }

        return validated;
    }

    private static bool IsValidHttpHeaderName(string headerName)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            return false;
        }

        const string allowedHeaderTokenSymbols = "!#$%&'*+-.^_`|~";

        foreach (var c in headerName)
        {
            if (char.IsLetterOrDigit(c))
            {
                continue;
            }

            if (allowedHeaderTokenSymbols.IndexOf(c) >= 0)
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool IsSafeHeaderValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c == '\r' || c == '\n' || char.IsControl(c))
            {
                return false;
            }
        }

        return true;
    }

    private OpenApiValidationSummary BuildTestSummary(OpenApiSpecificationValidation? specValidation, List<EndpointTestResult> endpointTests, OpenApiValidationOptions options)
    {
        var shouldIgnoreOptionalFailures = options.TestOptionalEndpoints && options.TreatOptionalEndpointsAsWarnings;
        var failedTests = endpointTests.Count(e =>
            (e.Status == EndpointTestStatus.FailedValidation || e.Status == EndpointTestStatus.Error) &&
            !(shouldIgnoreOptionalFailures && e.IsOptional));

        var summary = new OpenApiValidationSummary
        {
            TotalEndpoints = endpointTests.Count,
            TestedEndpoints = endpointTests.Count(e => e.IsTested),
            SuccessfulTests = endpointTests.Count(e => e.Status == EndpointTestStatus.PassedValidation),
            FailedTests = failedTests,
            SkippedTests = endpointTests.Count(e => e.Status == EndpointTestStatus.NotTested || e.Status == EndpointTestStatus.Skipped),
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
    private SchemaAnalysis AnalyzeSchemaStructure(JObject specObject)
    {
        var analysis = new SchemaAnalysis();

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

                    // Count headers
                    if (componentsObject.ContainsKey("headers"))
                    {
                        var headers = componentsObject["headers"];
                        if (headers is JObject headersObject)
                        {
                            analysis.HeaderCount = headersObject.Count;
                        }
                    }

                    // Count links
                    if (componentsObject.ContainsKey("links"))
                    {
                        var links = componentsObject["links"];
                        if (links is JObject linksObject)
                        {
                            analysis.LinkCount = linksObject.Count;
                        }
                    }

                    // Count callbacks
                    if (componentsObject.ContainsKey("callbacks"))
                    {
                        var callbacks = componentsObject["callbacks"];
                        if (callbacks is JObject callbacksObject)
                        {
                            analysis.CallbackCount = callbacksObject.Count;
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

            // Count examples throughout the specification
            analysis.ExampleCount = CountExamplesInSpec(specObject);

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
    /// Counts all example definitions throughout the OpenAPI specification
    /// </summary>
    private int CountExamplesInSpec(JObject specObject)
    {
        int exampleCount = 0;

        try
        {
            // Count examples in components section (OpenAPI 3.1+)
            if (specObject.ContainsKey("components"))
            {
                var components = specObject["components"];
                if (components is JObject componentsObject && componentsObject.ContainsKey("examples"))
                {
                    var examples = componentsObject["examples"];
                    if (examples is JObject examplesObject)
                    {
                        exampleCount += examplesObject.Count;
                    }
                }
            }

            // Count examples in paths - request bodies and responses
            if (specObject.ContainsKey("paths"))
            {
                var paths = specObject["paths"];
                if (paths is JObject pathsObject)
                {
                    foreach (var path in pathsObject.Properties())
                    {
                        if (path.Value is JObject pathObject)
                        {
                            // Check operations (get, post, put, delete, etc.)
                            foreach (var operation in pathObject.Properties())
                            {
                                if (operation.Value is JObject operationObject)
                                {
                                    // Count examples in request body
                                    if (operationObject.ContainsKey("requestBody"))
                                    {
                                        var requestBody = operationObject["requestBody"];
                                        if (requestBody is JObject requestBodyObject && requestBodyObject.ContainsKey("content"))
                                        {
                                            var content = requestBodyObject["content"];
                                            if (content is JObject contentObject)
                                            {
                                                foreach (var mediaType in contentObject.Properties())
                                                {
                                                    if (mediaType.Value is JObject mediaTypeObject)
                                                    {
                                                        if (mediaTypeObject.ContainsKey("example"))
                                                        {
                                                            exampleCount++;
                                                        }
                                                        if (mediaTypeObject.ContainsKey("examples"))
                                                        {
                                                            var examples = mediaTypeObject["examples"];
                                                            if (examples is JObject examplesObject)
                                                            {
                                                                exampleCount += examplesObject.Count;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Count examples in responses
                                    if (operationObject.ContainsKey("responses"))
                                    {
                                        var responses = operationObject["responses"];
                                        if (responses is JObject responsesObject)
                                        {
                                            foreach (var response in responsesObject.Properties())
                                            {
                                                if (response.Value is JObject responseObject && responseObject.ContainsKey("content"))
                                                {
                                                    var content = responseObject["content"];
                                                    if (content is JObject contentObject)
                                                    {
                                                        foreach (var mediaType in contentObject.Properties())
                                                        {
                                                            if (mediaType.Value is JObject mediaTypeObject)
                                                            {
                                                                if (mediaTypeObject.ContainsKey("example"))
                                                                {
                                                                    exampleCount++;
                                                                }
                                                                if (mediaTypeObject.ContainsKey("examples"))
                                                                {
                                                                    var examples = mediaTypeObject["examples"];
                                                                    if (examples is JObject examplesObject)
                                                                    {
                                                                        exampleCount += examplesObject.Count;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error counting examples in specification");
        }

        return exampleCount;
    }

    /// <summary>
    /// Analyzes quality metrics of the OpenAPI specification
    /// </summary>
    private QualityMetrics AnalyzeQualityMetrics(JObject specObject)
    {
        var metrics = new QualityMetrics();

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

    private void CountSchemaDescriptions(JObject specObject, QualityMetrics metrics)
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

    private void CalculateQualityScore(QualityMetrics metrics)
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
    private List<Recommendation> GenerateRecommendations(JObject specObject, List<ValidationError> errors)
    {
        var recommendations = new List<Recommendation>();

        try
        {
            // Convert errors to recommendations
            foreach (var error in errors.Where(e => e.Severity == "Error"))
            {
                recommendations.Add(new Recommendation
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
                recommendations.Add(new Recommendation
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

    private void AddQualityRecommendations(JObject specObject, List<Recommendation> recommendations)
    {
        // Check for missing info fields
        if (!specObject.ContainsKey("info") || specObject["info"] is not JObject infoObject)
        {
            return;
        }

        if (!infoObject.ContainsKey("description") || string.IsNullOrWhiteSpace(infoObject["description"]?.ToString()))
        {
            recommendations.Add(new Recommendation
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
            recommendations.Add(new Recommendation
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
            recommendations.Add(new Recommendation
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
        if (method == "GET" && result.TestResults.Any(r => r.IsSuccessStatusCode && !string.IsNullOrEmpty(r.ResponseBody)))
        {
            var rootPath = EndpointInfo.GetRootPath(path);
            var successfulResponse = result.TestResults.First(r => r.IsSuccessStatusCode);

            _logger.LogInformation("Processing HTTP response from {Url} (Status: {StatusCode}, ResponseSize: {Size} chars)",
                SchemaResolverService.SanitizeUrlForLogging(successfulResponse.RequestUrl ?? string.Empty),
                successfulResponse.ResponseStatusCode,
                successfulResponse.ResponseBody?.Length ?? 0);

            // Log first 500 characters of response for debugging
            var responsePreview = successfulResponse.ResponseBody!.Length > 500
                ? successfulResponse.ResponseBody[..500] + "..."
                : successfulResponse.ResponseBody;

            _logger.LogDebug("Response content length: {Length} chars", successfulResponse.ResponseBody?.Length ?? 0);

            var ids = ExtractIdsFromResponse(successfulResponse.ResponseBody!, rootPath, operation, openApiDocument);

            if (ids.Any())
            {
                // Store extracted IDs in the shared dictionary for use by dependent endpoints
                // Note: ConcurrentDictionary is a reference type, so this modification persists to the caller
                extractedIds[rootPath] = ids;
                _logger.LogInformation("✅ Successfully extracted and stored {Count} IDs from {Path} for root path '{RootPath}'",
                    ids.Count, SanitizeForLogging(path), SanitizeForLogging(rootPath));

                // Verify the IDs were stored correctly
                if (extractedIds.TryGetValue(rootPath, out var storedIds))
                {
                    _logger.LogDebug("✅ Verified: {Count} IDs successfully stored in extractedIds dictionary for '{RootPath}'",
                        storedIds.Count, SanitizeForLogging(rootPath));
                }
                else
                {
                    _logger.LogWarning("⚠️ Warning: IDs extraction appeared successful but verification failed for '{RootPath}'", SanitizeForLogging(rootPath));
                }
            }
            else
            {
                _logger.LogWarning("No IDs could be extracted from response for path {Path} (root: {RootPath})", SanitizeForLogging(path), SanitizeForLogging(rootPath));
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
        var rootPath = EndpointInfo.GetRootPath(path);

        _logger.LogInformation("🔍 Looking for extracted IDs for root path '{RootPath}'. Available keys count: {Count}",
            SanitizeForLogging(rootPath), extractedIds.Keys.Count);

        // Try to retrieve extracted IDs from the shared dictionary populated by collection endpoint tests
        if (extractedIds.TryGetValue(rootPath, out var availableIds) && availableIds.Any())
        {
            _logger.LogInformation("✅ Found {Count} extracted IDs for root path '{RootPath}'",
                availableIds.Count, SanitizeForLogging(rootPath));

            // Test up to 10 random IDs from the available IDs
            var maxIdsToTest = Math.Min(10, availableIds.Count);
            var random = new Random();
            var idsToTest = availableIds.Count <= 10
                ? availableIds.ToList()
                : availableIds.OrderBy(_ => random.Next()).Take(10).ToList();

            _logger.LogInformation("🎯 Testing {Count} random IDs for endpoint {Path}", idsToTest.Count, SanitizeForLogging(path));

            // Create a composite result that combines all test results
            var compositeResult = new EndpointTestResult
            {
                Path = path,
                Method = method,
                Name = operation["name"]?.ToString(),
                OperationId = operation["operationId"]?.ToString(),
                Summary = operation["summary"]?.ToString(),
                IsOptional = operation.IsOptionalEndpoint(),
                Status = EndpointTestStatus.NotTested,
                IsTested = false
            };

            // Test each ID
            var allTestsSuccessful = true;
            var hasSkippedResult = false;
            foreach (var id in idsToTest)
            {
                var substitutedPath = SubstitutePathParametersWithSpecificId(path, id);
                _logger.LogDebug("Testing endpoint with extracted ID (path sanitized for security)");

                var singleResult = await TestSingleEndpointAsync(substitutedPath, method, operation, baseUrl, options, authentication, semaphore, openApiDocument, documentUri, pathItem, cancellationToken, testedId: id);

                // Aggregate the results
                compositeResult.TestResults.AddRange(singleResult.TestResults);
                //compositeResult.ValidationErrors.AddRange(singleResult.ValidationErrors);
                //compositeResult.SchemaValidationDetails.AddRange(singleResult.SchemaValidationDetails);

                if (singleResult.Status == EndpointTestStatus.Skipped)
                {
                    hasSkippedResult = true;
                }

                if (singleResult.Status == EndpointTestStatus.FailedValidation || singleResult.Status == EndpointTestStatus.Error)
                {
                    allTestsSuccessful = false;
                }
            }

            compositeResult.IsTested = compositeResult.TestResults.Any();

            // Set the composite status based on all test results
            if (compositeResult.TestResults.Any())
            {
                if (allTestsSuccessful)
                {
                    compositeResult.Status = EndpointTestStatus.PassedValidation;
                }
                else if (compositeResult.TestResults.Any(tr => tr.ValidationResult != null && tr.ValidationResult.Errors.Any(e => e.Severity == "Warning")) && !compositeResult.TestResults.Any(tr => tr.ValidationResult != null && tr.ValidationResult.Errors.Any(e => e.Severity == "Error")))
                {
                    compositeResult.Status = EndpointTestStatus.PassedWithWarnings;
                }
                else
                {
                    compositeResult.Status = EndpointTestStatus.FailedValidation;
                }
            }
            else if (hasSkippedResult)
            {
                compositeResult.Status = EndpointTestStatus.Skipped;
            }

            return compositeResult;
        }
        else
        {
            _logger.LogWarning("⚠️ No extracted IDs available for root path '{RootPath}'. Dictionary contains {KeyCount} entries. Marking endpoint as NotTested: {Path}",
                SanitizeForLogging(rootPath), extractedIds.Count, SanitizeForLogging(path));

            // Log available keys for debugging
            if (extractedIds.Any())
            {
                _logger.LogDebug("Available ID keys count in dictionary: {Count}", extractedIds.Keys.Count);
            }

            // Return a NotTested result instead of falling back to default values
            var notTestedResult = new EndpointTestResult
            {
                Path = path,
                Method = method,
                Name = operation["name"]?.ToString(),
                OperationId = operation["operationId"]?.ToString(),
                Summary = operation["summary"]?.ToString(),
                IsOptional = operation.IsOptionalEndpoint(),
                Status = EndpointTestStatus.NotTested,
                IsTested = false,
                TestResults = new List<HttpTestResult>(){
                    new() {
                        IsSuccessStatusCode = false,
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

            NormalizeValidationResultErrors(notTestedResult.TestResults.FirstOrDefault()?.ValidationResult);
            return notTestedResult;
        }
    }

    /// <summary>
    /// Extracts IDs from a JSON response using OpenAPI schema information to identify ID field locations
    /// </summary>
    private List<string> ExtractIdsFromResponse(string responseBody, string rootPath, JObject operation, JObject openApiDocument)
    {
        var ids = new List<string>();

        _logger.LogInformation("Starting ID extraction from JSON response for root path: {RootPath}", SanitizeForLogging(rootPath));

        // First, try to extract ID field names from the OpenAPI schema
        var schemaIdFields = ExtractIdFieldsFromSchema(operation, openApiDocument);
        if (schemaIdFields.Any())
        {
            _logger.LogDebug("Found {Count} ID fields from OpenAPI schema", schemaIdFields.Count);
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
                        _logger.LogDebug("Found ID in array item (ID hidden for security)");
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
                    var sanitizedProps = string.Join(", ", collectionProps.Select(p => SanitizeForLogging(p)));
                    _logger.LogDebug("Found collection properties from OpenAPI schema: [{CollectionProps}]", sanitizedProps);

                    foreach (var propName in collectionProps)
                    {
                        if (obj[propName] is JArray items)
                        {
                            _logger.LogDebug("Processing collection property '{PropName}' with {Count} items", SanitizeForLogging(propName), items.Count);
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
                            _logger.LogDebug("Processing fallback collection property '{PropName}' with {Count} items", SanitizeForLogging(propName), items.Count);
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
            _logger.LogWarning(ex, "Failed to extract IDs from response for path {Path}", SanitizeForLogging(rootPath));
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
    /// Sanitizes a string for safe inclusion in log messages by removing control characters.
    /// </summary>
    /// <param name="value">The value to sanitize.</param>
    /// <returns>A sanitized string safe for logging.</returns>
    private static string SanitizeForLogging(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        // Remove carriage returns and newlines to prevent log forging
        var sanitized = value.Replace("\r", string.Empty)
                             .Replace("\n", string.Empty);

        return sanitized;
    }

    /// <summary>
    /// Applies authentication to an HTTP request based on the provided authentication configuration
    /// Supports API key, bearer token, basic authentication, and custom headers
    /// </summary>
    /// <param name="request">The HTTP request message to apply authentication to</param>
    /// <param name="authentication">The authentication configuration containing credentials and auth type</param>
    private void ApplyAuthenticationHeaders(HttpRequestMessage request, IAuthenticationConfig authentication)
    {
        // Apply API Key authentication
        if (!string.IsNullOrEmpty(authentication.ApiKey))
        {
            var headerName = string.IsNullOrEmpty(authentication.ApiKeyHeader) ? "X-API-Key" : authentication.ApiKeyHeader;
            if (IsValidHttpHeaderName(headerName) && IsSafeHeaderValue(authentication.ApiKey))
            {
                request.Headers.Add(headerName, authentication.ApiKey);
                _logger.LogDebug("Applied API Key authentication with header: {HeaderName}", SanitizeForLogging(headerName));
            }
            else
            {
                _logger.LogWarning("Skipped API Key authentication due to invalid header name or value");
            }
        }

        // Apply Bearer Token authentication
        if (!string.IsNullOrEmpty(authentication.BearerToken))
        {
            if (IsSafeHeaderValue(authentication.BearerToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authentication.BearerToken);
                _logger.LogDebug("Applied Bearer Token authentication");
            }
            else
            {
                _logger.LogWarning("Skipped Bearer Token authentication due to invalid token value");
            }
        }

        // Apply Basic Authentication
        if (authentication.BasicAuth != null &&
            !string.IsNullOrEmpty(authentication.BasicAuth.Username))
        {
            var credentials = Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{authentication.BasicAuth.Username}:{authentication.BasicAuth.Password ?? string.Empty}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            _logger.LogDebug("Applied Basic authentication for user: {Username}", SanitizeForLogging(authentication.BasicAuth.Username));
        }

        // Apply Custom Headers
        if (authentication.CustomHeaders != null && authentication.CustomHeaders.Any())
        {
            foreach (var header in authentication.CustomHeaders)
            {
                if (!string.IsNullOrEmpty(header.Key) &&
                    !string.IsNullOrEmpty(header.Value) &&
                    IsValidHttpHeaderName(header.Key) &&
                    IsSafeHeaderValue(header.Value))
                {
                    request.Headers.Add(header.Key, header.Value);
                    _logger.LogDebug("Applied custom header: {HeaderName}", SanitizeForLogging(header.Key));
                }
                else
                {
                    _logger.LogWarning("Skipped invalid custom header");
                }
            }
        }
    }
}

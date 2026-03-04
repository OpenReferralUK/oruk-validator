using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Maps OpenAPI validation results to the standard ValidationResponse format
/// </summary>
public interface IOpenApiToValidationResponseMapper
{
    object MapToValidationResponse(OpenApiValidationResult openApiResult);
}

public class OpenApiToValidationResponseMapper : IOpenApiToValidationResponseMapper
{
    public object MapToValidationResponse(OpenApiValidationResult openApiResult)
    {
        var testSuites = new List<object>();

        // Map endpoint tests to test groups - separate required and optional endpoints
        if (openApiResult.EndpointTests != null && openApiResult.EndpointTests.Any())
        {
            var requiredEndpoints = openApiResult.EndpointTests.Where(e => !e.IsOptional).ToList();
            var optionalEndpoints = openApiResult.EndpointTests.Where(e => e.IsOptional).ToList();

            if (requiredEndpoints.Any())
            {
                testSuites.Add(MapEndpointTests(requiredEndpoints, openApiResult?.Metadata?.BaseUrl ?? "", 
                    "Level 1 Compliance - Basic checks", 
                    "Will validate the required basic endpoints. Validation will fail if it does not pass all these checks.", 
                    true));
            }

            if (optionalEndpoints.Any())
            {
                testSuites.Add(MapEndpointTests(optionalEndpoints, openApiResult?.Metadata?.BaseUrl ?? "", 
                    "Level 2 Compliance - Extended checks", 
                    "Will validate all other endpoints. Validation will not fail if it does not pass all these checks.", 
                    false));
            }
        }

        // Determine overall validity
        bool isValid = openApiResult?.IsValid ?? false && 
                       openApiResult?.Summary?.FailedTests == 0 && 
                       (openApiResult?.SpecificationValidation?.IsValid ?? true);

        return new
        {
            service = new
            {
                url = openApiResult?.Metadata?.BaseUrl ?? "",
                isValid = isValid,
                profile = $"{openApiResult?.SpecificationValidation?.Version ?? "Unknown"}",
                profileReason = openApiResult?.Metadata?.ProfileReason ?? "Unknown"
            },
            testSuites = testSuites
        };
    }

    private object MapEndpointTests(List<EndpointTestResult> endpointTests, string baseUrl, 
        string name, string description, bool required)
    {
        var tests = endpointTests.Select(endpoint => 
        {
            // Find the first failed test if any
            var firstFailedTest = endpoint.TestResults.FirstOrDefault(tr => tr.ValidationResult != null && !tr.ValidationResult.IsValid);
            var testToUse = firstFailedTest ?? endpoint.TestResults.FirstOrDefault();
            
            return new
            {
                name = endpoint.Name ?? $"{endpoint.Method} {endpoint.Path}",
                endpoint = $"{baseUrl}{endpoint.Path}",
                description = endpoint.Summary ?? endpoint.OperationId ?? "Endpoint test",
                id = testToUse?.TestedId,
                success = firstFailedTest == null && endpoint.TestResults.Any(tr => tr.ValidationResult != null && tr.ValidationResult.IsValid),
                messages = MapEndpointMessages(endpoint, firstFailedTest)
            };
        }).ToList();

        return new
        {
            name = name,
            description = description,
            messageLevel = required ? "error" : "warning",
            required = required,
            success = endpointTests.All(e => e.Status == "Success" || e.Status == "Warning"),
            tests = tests
        };
    }

    private List<object> MapEndpointMessages(EndpointTestResult endpoint, HttpTestResult? specificTest = null)
    {
        var messages = new List<object>();

        // Add schema validation issues from test results
        // If a specific test is provided (first failed), use only that one
        var testsToProcess = specificTest != null 
            ? new[] { specificTest } 
            : endpoint.TestResults.Where(tr => tr.ValidationResult != null && !tr.ValidationResult.IsValid).Take(1);
            
        foreach (var testResult in testsToProcess)
        {
            if (testResult.ValidationResult != null && !testResult.ValidationResult.IsValid)
            {
                foreach (var validationError in testResult.ValidationResult.Errors.Take(1))
                {
                    messages.Add(new
                    {
                        name = validationError.ErrorCode,
                        description = validationError.Severity,
                        message = validationError.Message,
                        errorIn = validationError.Path,
                        errorAt = ""
                    });
                }
            }
        }

        // If endpoint succeeded but had performance issues, add info messages
        if (endpoint.Status == "Success" && endpoint.TestResults.Any())
        {
            var avgResponseTime = endpoint.TestResults
                .Where(tr => tr.ResponseTime > TimeSpan.Zero)
                .Average(tr => tr.ResponseTime.TotalMilliseconds);

            if (avgResponseTime > 5000) // Slow response warning
            {
                messages.Add(new
                {
                    name = "Performance",
                    description = "Warning",
                    message = $"Average response time is {avgResponseTime:F0}ms, which may be slow",
                    errorIn = endpoint.Path,
                    errorAt = ""
                });
            }
        }

        return messages;
    }
}

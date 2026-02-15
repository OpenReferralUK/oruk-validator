using System;
using System.Text.Json.Nodes;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Core.Services;

/// <summary>
/// Extensions and utilities for handling optional endpoints in OpenAPI validation
/// </summary>
public static class OptionalEndpointExtensions
{
    /// <summary>
    /// Determines if an endpoint is marked as optional in the OpenAPI specification
    /// </summary>
    /// <param name="pathItem">The path item object from the OpenAPI spec</param>
    /// <returns>True if the endpoint is optional, false if required</returns>
    public static bool IsOptionalEndpoint(this JsonNode? pathItem)
    {
        if (pathItem is JsonObject pathObject)
        {
            return HasOptionalTag(pathObject);
        }

        // Default to required if no optional markers found
        return false;
    }

    /// <summary>
    /// Checks if an operation has the "Optional" tag indicating it's an optional endpoint
    /// </summary>
    /// <param name="pathObject">The path item or operation object from the OpenAPI spec</param>
    /// <returns>True if the operation has the "Optional" tag</returns>
    private static bool HasOptionalTag(JsonObject pathObject)
    {
        // Check if this is an operation object with tags
        if (pathObject.TryGetPropertyValue("tags", out var tags) && tags is JsonArray tagsArray)
        {
            foreach (var tag in tagsArray)
            {
                if (tag?.GetValue<string>().Equals("Optional", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return true;
                }
            }
        }

        // If this is a path item, check all operations within it
        var httpMethods = new[] { "get", "post", "put", "delete", "patch", "head", "options", "trace" };
        foreach (var method in httpMethods)
        {
            if (pathObject.TryGetPropertyValue(method, out var operation) && operation is JsonObject operationObject)
            {
                if (operationObject.TryGetPropertyValue("tags", out var operationTags) && operationTags is JsonArray operationTagsArray)
                {
                    foreach (var tag in operationTagsArray)
                    {
                        if (tag?.GetValue<string>().Equals("Optional", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Gets the optional endpoint category for grouping validation results
    /// </summary>
    /// <param name="pathItem">The path item object from the OpenAPI spec</param>
    /// <returns>The category name or null if not specified</returns>
    public static string? GetOptionalEndpointCategory(this JsonNode? pathItem)
    {
        if (pathItem is JsonObject pathObject)
        {
            var tags = GetEndpointTags(pathObject);
            if (tags != null && tags.Any())
            {
                // Return the first tag as the category, excluding "Optional" 
                var categoryTag = tags.FirstOrDefault(tag =>
                    !tag.Equals("Optional", StringComparison.OrdinalIgnoreCase));

                if (!string.IsNullOrEmpty(categoryTag))
                {
                    return categoryTag;
                }

                // If no other tags, return "Optional" for optional endpoints, null for required (default)
                if (tags.Any(tag => tag.Equals("Optional", StringComparison.OrdinalIgnoreCase)))
                {
                    return "Optional";
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Gets all tags for an endpoint operation
    /// </summary>
    /// <param name="pathObject">The path item or operation object from the OpenAPI spec</param>
    /// <returns>List of tags or null if none found</returns>
    private static List<string>? GetEndpointTags(JsonObject pathObject)
    {
        // Check if this is an operation object with tags
        if (pathObject.TryGetPropertyValue("tags", out var tags) && tags is JsonArray tagsArray)
        {
            var tagList = new List<string>();
            foreach (var tag in tagsArray)
            {
                var tagValue = tag?.GetValue<string>();
                if (!string.IsNullOrEmpty(tagValue))
                {
                    tagList.Add(tagValue);
                }
            }
            return tagList;
        }

        // If this is a path item, get tags from all operations within it
        var allTags = new HashSet<string>();
        var httpMethods = new[] { "get", "post", "put", "delete", "patch", "head", "options", "trace" };
        foreach (var method in httpMethods)
        {
            if (pathObject.TryGetPropertyValue(method, out var operation) && operation is JsonObject operationObject)
            {
                if (operationObject.TryGetPropertyValue("tags", out var operationTags) && operationTags is JsonArray operationTagsArray)
                {
                    foreach (var tag in operationTagsArray)
                    {
                        var tagValue = tag?.GetValue<string>();
                        if (!string.IsNullOrEmpty(tagValue))
                        {
                            allTags.Add(tagValue);
                        }
                    }
                }
            }
        }

        return allTags.Count > 0 ? allTags.ToList() : null;
    }

    /// <summary>
    /// Determines if a response status code indicates an unimplemented optional endpoint
    /// </summary>
    /// <param name="statusCode">HTTP status code</param>
    /// <param name="isOptionalEndpoint">Whether the endpoint is marked as optional</param>
    /// <returns>True if the status code indicates acceptable non-implementation</returns>
    public static bool IsAcceptableOptionalEndpointResponse(int statusCode, bool isOptionalEndpoint)
    {
        if (!isOptionalEndpoint)
            return false;

        // Status codes that indicate acceptable non-implementation of optional endpoints
        return statusCode switch
        {
            404 => true,  // Not Found - endpoint not implemented
            501 => true,  // Not Implemented - feature not implemented
            503 => true,  // Service Unavailable - temporarily not available (acceptable for optional)
            _ => false
        };
    }

    /// <summary>
    /// Validates that the response conforms to the specification for optional endpoints
    /// </summary>
    /// <param name="statusCode">HTTP response status code</param>
    /// <param name="pathItem">The path item from the OpenAPI spec</param>
    /// <returns>Validation result with specific handling for optional endpoints</returns>
    public static OptionalEndpointValidationResult ValidateOptionalEndpointResponse(
        int statusCode,
        JsonNode? pathItem)
    {
        var result = new OptionalEndpointValidationResult
        {
            IsOptional = pathItem.IsOptionalEndpoint(),
            StatusCode = statusCode,
            Category = pathItem.GetOptionalEndpointCategory()
        };

        if (result.IsOptional)
        {
            // For optional endpoints, check if non-implementation is acceptable
            if (IsAcceptableOptionalEndpointResponse(statusCode, true))
            {
                result.ValidationStatus = OptionalEndpointStatus.NotImplemented;
                result.Message = $"Optional endpoint not implemented (HTTP {statusCode}) - this is acceptable";
                result.IsValid = true;
            }
            else if (statusCode >= 200 && statusCode < 300)
            {
                result.ValidationStatus = OptionalEndpointStatus.Implemented;
                result.Message = "Optional endpoint is implemented and should conform to specification";
                result.IsValid = true; // Will need further schema validation
                result.RequiresSchemaValidation = true;
            }
            else
            {
                result.ValidationStatus = OptionalEndpointStatus.Error;
                result.Message = $"Optional endpoint returned error status {statusCode}";
                result.IsValid = false;
            }
        }
        else
        {
            // Required endpoint - standard validation applies
            result.ValidationStatus = OptionalEndpointStatus.Required;
            result.IsValid = statusCode >= 200 && statusCode < 300;
            result.RequiresSchemaValidation = result.IsValid;
            result.Message = result.IsValid ? "Required endpoint responded successfully" : $"Required endpoint failed with status {statusCode}";
        }

        return result;
    }
}


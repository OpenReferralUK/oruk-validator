using System.Text.Json.Nodes;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class OptionalEndpointExtensionsTests
{
    #region IsOptionalEndpoint Tests

    [Test]
    public void IsOptionalEndpoint_WithOptionalTag_ReturnsTrue()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsOptionalEndpoint_WithoutOptionalTag_ReturnsFalse()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsOptionalEndpoint_WithOptionalTagCaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""optional"", ""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsOptionalEndpoint_WithMultipleMethods_ReturnsTrue()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            },
            ""post"": {
                ""tags"": [""Optional""],
                ""summary"": ""Create user""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsOptionalEndpoint_WithNoTags_ReturnsFalse()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsOptionalEndpoint_WithEmptyPathItem_ReturnsFalse()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"{}");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsOptionalEndpoint_WithNonObjectToken_ReturnsFalse()
    {
        // Arrange
        var pathItem = JsonValue.Create("not an object");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.False);
    }

    #endregion

    #region GetOptionalEndpointCategory Tests

    [Test]
    public void GetOptionalEndpointCategory_WithMultipleTags_ReturnsFirstNonOptional()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional"", ""Users"", ""Public""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.Not.EqualTo("Optional"));
        Assert.That(result, Is.AnyOf("Users", "Public"));
    }

    [Test]
    public void GetOptionalEndpointCategory_WithOnlyOptionalTag_ReturnsOptional()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.EqualTo("Optional"));
    }

    [Test]
    public void GetOptionalEndpointCategory_WithNoTags_ReturnsNull()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetOptionalEndpointCategory_WithRequiredEndpoint_ReturnsCategory()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.EqualTo("Users"));
    }

    [Test]
    public void GetOptionalEndpointCategory_WithPathLevelAndOperationLevelTags_CombinesTags()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional"", ""Users""],
                ""summary"": ""Get users""
            },
            ""post"": {
                ""tags"": [""Public""],
                ""summary"": ""Create user""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region IsAcceptableOptionalEndpointResponse Tests

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With404_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(404, isOptionalEndpoint: true);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With501_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(501, isOptionalEndpoint: true);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With503_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(503, isOptionalEndpoint: true);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With500_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(500, isOptionalEndpoint: true);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With200_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(200, isOptionalEndpoint: true);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_RequiredEndpoint_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(404, isOptionalEndpoint: false);

        // Assert
        Assert.That(result, Is.False);
    }

    #endregion

    #region ValidateOptionalEndpointResponse Tests

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointNotImplemented_ReturnsNotImplementedStatus()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(404, pathItem);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsOptional, Is.True);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.NotImplemented));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.StatusCode, Is.EqualTo(404));
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointImplemented_ReturnsImplementedStatus()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsOptional, Is.True);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.Implemented));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.RequiresSchemaValidation, Is.True);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointWithErrorStatus_ReturnsErrorStatus()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(500, pathItem);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsOptional, Is.True);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.Error));
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_RequiredEndpointSuccess_ReturnsRequiredStatus()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsOptional, Is.False);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.Required));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.RequiresSchemaValidation, Is.True);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_RequiredEndpointFailure_ReturnsInvalid()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(500, pathItem);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsOptional, Is.False);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.Required));
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.RequiresSchemaValidation, Is.False);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_IncludesCategory()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional"", ""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        Assert.That(result.Category, Is.Not.Null);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_With201Created_ReturnsSuccess()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""post"": {
                ""summary"": ""Create user""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(201, pathItem);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.Required));
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointWith503_ReturnsNotImplementedStatus()
    {
        // Arrange - 503 is acceptable as non-implementation for optional endpoints
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(503, pathItem);

        // Assert
        Assert.That(result.IsOptional, Is.True);
        Assert.That(result.ValidationStatus, Is.EqualTo(OptionalEndpointStatus.NotImplemented));
        Assert.That(result.IsValid, Is.True);
    }

    #endregion

    #region Multiple Methods Tests

    [Test]
    public void ValidateOptionalEndpointResponse_WithMultipleHttpMethods_EvaluatesAllOperations()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            },
            ""post"": {
                ""summary"": ""Create user""
            },
            ""put"": {
                ""tags"": [""Optional""],
                ""summary"": ""Update user""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region Edge Cases Tests

    [Test]
    public void IsOptionalEndpoint_WithArrayOfTags_HandlesProperly()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users"", ""Optional"", ""Public""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_With404AndOptionalTrue_IsValid()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(404, pathItem);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Message, Does.Contain("acceptable"));
    }

    [Test]
    public void GetOptionalEndpointCategory_WithPathItem_ExtractsFromAllOperations()
    {
        // Arrange
        var pathItem = JsonNode.Parse(@"
        {
            ""get"": {
                ""tags"": [""API"", ""Read""],
                ""summary"": ""Get users""
            },
            ""delete"": {
                ""tags"": [""Optional"", ""Delete""],
                ""summary"": ""Delete user""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion
}


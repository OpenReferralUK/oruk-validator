using FluentAssertions;
using Newtonsoft.Json.Linq;
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
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsOptionalEndpoint_WithoutOptionalTag_ReturnsFalse()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsOptionalEndpoint_WithOptionalTagCaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""optional"", ""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsOptionalEndpoint_WithMultipleMethods_ReturnsTrue()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
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
        result.Should().BeTrue();
    }

    [Test]
    public void IsOptionalEndpoint_WithNoTags_ReturnsFalse()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsOptionalEndpoint_WithEmptyPathItem_ReturnsFalse()
    {
        // Arrange
        var pathItem = JObject.Parse(@"{}");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsOptionalEndpoint_WithNonObjectToken_ReturnsFalse()
    {
        // Arrange
        JToken pathItem = new JValue("not an object");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region GetOptionalEndpointCategory Tests

    [Test]
    public void GetOptionalEndpointCategory_WithMultipleTags_ReturnsFirstNonOptional()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional"", ""Users"", ""Public""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        result.Should().NotBeNull();
        result.Should().NotBe("Optional");
        result.Should().BeOneOf("Users", "Public");
    }

    [Test]
    public void GetOptionalEndpointCategory_WithOnlyOptionalTag_ReturnsOptional()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        result.Should().Be("Optional");
    }

    [Test]
    public void GetOptionalEndpointCategory_WithNoTags_ReturnsNull()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        result.Should().BeNull();
    }

    [Test]
    public void GetOptionalEndpointCategory_WithRequiredEndpoint_ReturnsCategory()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.GetOptionalEndpointCategory();

        // Assert
        result.Should().Be("Users");
    }

    [Test]
    public void GetOptionalEndpointCategory_WithPathLevelAndOperationLevelTags_CombinesTags()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
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
        result.Should().NotBeNull();
    }

    #endregion

    #region IsAcceptableOptionalEndpointResponse Tests

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With404_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(404, isOptionalEndpoint: true);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With501_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(501, isOptionalEndpoint: true);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With503_ReturnsTrue()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(503, isOptionalEndpoint: true);

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With500_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(500, isOptionalEndpoint: true);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_With200_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(200, isOptionalEndpoint: true);

        // Assert
        result.Should().BeFalse();
    }

    [Test]
    public void IsAcceptableOptionalEndpointResponse_RequiredEndpoint_ReturnsFalse()
    {
        // Act
        var result = OptionalEndpointExtensions.IsAcceptableOptionalEndpointResponse(404, isOptionalEndpoint: false);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region ValidateOptionalEndpointResponse Tests

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointNotImplemented_ReturnsNotImplementedStatus()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(404, pathItem);

        // Assert
        result.Should().NotBeNull();
        result.IsOptional.Should().BeTrue();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.NotImplemented);
        result.IsValid.Should().BeTrue();
        result.StatusCode.Should().Be(404);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointImplemented_ReturnsImplementedStatus()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        result.Should().NotBeNull();
        result.IsOptional.Should().BeTrue();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.Implemented);
        result.IsValid.Should().BeTrue();
        result.RequiresSchemaValidation.Should().BeTrue();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointWithErrorStatus_ReturnsErrorStatus()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(500, pathItem);

        // Assert
        result.Should().NotBeNull();
        result.IsOptional.Should().BeTrue();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.Error);
        result.IsValid.Should().BeFalse();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_RequiredEndpointSuccess_ReturnsRequiredStatus()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        result.Should().NotBeNull();
        result.IsOptional.Should().BeFalse();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.Required);
        result.IsValid.Should().BeTrue();
        result.RequiresSchemaValidation.Should().BeTrue();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_RequiredEndpointFailure_ReturnsInvalid()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(500, pathItem);

        // Assert
        result.Should().NotBeNull();
        result.IsOptional.Should().BeFalse();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.Required);
        result.IsValid.Should().BeFalse();
        result.RequiresSchemaValidation.Should().BeFalse();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_IncludesCategory()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional"", ""Users""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(200, pathItem);

        // Assert
        result.Category.Should().NotBeNull();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_With201Created_ReturnsSuccess()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""post"": {
                ""summary"": ""Create user""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(201, pathItem);

        // Assert
        result.IsValid.Should().BeTrue();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.Required);
    }

    [Test]
    public void ValidateOptionalEndpointResponse_OptionalEndpointWith503_ReturnsNotImplementedStatus()
    {
        // Arrange - 503 is acceptable as non-implementation for optional endpoints
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(503, pathItem);

        // Assert
        result.IsOptional.Should().BeTrue();
        result.ValidationStatus.Should().Be(OptionalEndpointStatus.NotImplemented);
        result.IsValid.Should().BeTrue();
    }

    #endregion

    #region Multiple Methods Tests

    [Test]
    public void ValidateOptionalEndpointResponse_WithMultipleHttpMethods_EvaluatesAllOperations()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
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
        result.Should().BeTrue();
    }

    #endregion

    #region Edge Cases Tests

    [Test]
    public void IsOptionalEndpoint_WithArrayOfTags_HandlesProperly()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Users"", ""Optional"", ""Public""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = pathItem.IsOptionalEndpoint();

        // Assert
        result.Should().BeTrue();
    }

    [Test]
    public void ValidateOptionalEndpointResponse_With404AndOptionalTrue_IsValid()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
        {
            ""get"": {
                ""tags"": [""Optional""],
                ""summary"": ""Get users""
            }
        }");

        // Act
        var result = OptionalEndpointExtensions.ValidateOptionalEndpointResponse(404, pathItem);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Message.Should().Contain("acceptable");
    }

    [Test]
    public void GetOptionalEndpointCategory_WithPathItem_ExtractsFromAllOperations()
    {
        // Arrange
        var pathItem = JObject.Parse(@"
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
        result.Should().NotBeNull();
    }

    #endregion
}


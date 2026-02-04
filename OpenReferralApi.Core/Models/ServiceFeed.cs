using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json.Serialization;

namespace OpenReferralApi.Core.Models;

/// <summary>
/// Represents a registered service feed in the MongoDB database
/// </summary>
[BsonIgnoreExtraElements]
public class ServiceFeed
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("service")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonDocument? Service { get; set; }

    [BsonElement("url")]
    [JsonIgnore]
    public string? UrlField { get; set; }

    /// <summary>
    /// Helper property to get URL from service.url or fallback to url field
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("url")]
    public string Url
    {
        get
        {
            // Try to get URL from service.url first
            if (Service != null && Service.Contains("url"))
            {
                var urlValue = Service["url"];
                if (urlValue != null && urlValue.IsString)
                {
                    return urlValue.AsString;
                }
            }
            // Fallback to the url field
            return UrlField ?? string.Empty;
        }
    }

    [BsonElement("name")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonDocument? Name { get; set; }

    /// <summary>
    /// Helper property to get name as string
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("name")]
    public string? NameAsString => Name?.ToString();

    [BsonElement("active")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? ActiveField { get; set; }

    /// <summary>
    /// Helper property to get active as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("active")]
    public bool IsActive
    {
        get
        {
            if (ActiveField == null) return false;
            if (ActiveField.IsBoolean) return ActiveField.AsBoolean;
            if (ActiveField.IsString) return ActiveField.AsString.ToLowerInvariant() == "true";
            return false;
        }
    }

    [BsonElement("statusIsUp")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusIsUp { get; set; }

    /// <summary>
    /// Helper property to get statusIsUp as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusIsUp")]
    public bool IsUp
    {
        get
        {
            if (StatusIsUp == null) return false;
            if (StatusIsUp.IsBoolean) return StatusIsUp.AsBoolean;
            if (StatusIsUp.IsString) return StatusIsUp.AsString.ToLowerInvariant() == "true";
            // Handle nested object with value field
            if (StatusIsUp.IsBsonDocument)
            {
                var doc = StatusIsUp.AsBsonDocument;
                if (doc.Contains("value"))
                {
                    var val = doc["value"];
                    if (val.IsBoolean) return val.AsBoolean;
                    if (val.IsString) return val.AsString.ToLowerInvariant() == "true";
                }
            }
            return false;
        }
    }

    [BsonElement("statusIsValid")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusIsValid { get; set; }

    /// <summary>
    /// Helper property to get statusIsValid as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusIsValid")]
    public bool IsValid
    {
        get
        {
            if (StatusIsValid == null) return false;
            if (StatusIsValid.IsBoolean) return StatusIsValid.AsBoolean;
            if (StatusIsValid.IsString) return StatusIsValid.AsString.ToLowerInvariant() == "true";
            // Handle nested object with value field
            if (StatusIsValid.IsBsonDocument)
            {
                var doc = StatusIsValid.AsBsonDocument;
                if (doc.Contains("value"))
                {
                    var val = doc["value"];
                    if (val.IsBoolean) return val.AsBoolean;
                    if (val.IsString) return val.AsString.ToLowerInvariant() == "true";
                }
            }
            return false;
        }
    }

    [BsonElement("statusOverall")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusOverall { get; set; }

    /// <summary>
    /// Helper property to get statusOverall as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusOverall")]
    public bool IsOverallValid
    {
        get
        {
            if (StatusOverall == null) return false;
            if (StatusOverall.IsBoolean) return StatusOverall.AsBoolean;
            if (StatusOverall.IsString) return StatusOverall.AsString.ToLowerInvariant() == "true";
            // Handle nested object with value field
            if (StatusOverall.IsBsonDocument)
            {
                var doc = StatusOverall.AsBsonDocument;
                if (doc.Contains("value"))
                {
                    var val = doc["value"];
                    if (val.IsBoolean) return val.AsBoolean;
                    if (val.IsString) return val.AsString.ToLowerInvariant() == "true";
                }
            }
            return false;
        }
    }

    [BsonElement("testDate")]
    public DateTime? TestDate { get; set; }

    [BsonElement("lastError")]
    public string? LastError { get; set; }

    [BsonElement("responseTime")]
    public double? ResponseTimeMs { get; set; }

    [BsonElement("validationErrors")]
    public int? ValidationErrorCount { get; set; }
}

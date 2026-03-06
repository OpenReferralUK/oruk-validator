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
    public string Url => ServiceFeedMapper.GetUrl(this);

    [BsonElement("name")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonDocument? Name { get; set; }

    /// <summary>
    /// Helper property to get name as string
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("name")]
    public string? NameAsString => ServiceFeedMapper.GetNameAsString(this);

    [BsonElement("active")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? ActiveField { get; set; }

    /// <summary>
    /// Helper property to get active as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("active")]
    public bool IsActive => ServiceFeedMapper.GetBoolean(ActiveField);

    [BsonElement("statusIsUp")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusIsUp { get; set; }

    /// <summary>
    /// Helper property to get statusIsUp as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusIsUp")]
    public bool IsUp => ServiceFeedMapper.GetBoolean(StatusIsUp);

    [BsonElement("statusIsValid")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusIsValid { get; set; }

    /// <summary>
    /// Helper property to get statusIsValid as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusIsValid")]
    public bool IsValid => ServiceFeedMapper.GetBoolean(StatusIsValid);

    [BsonElement("statusOverall")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? StatusOverall { get; set; }

    /// <summary>
    /// Helper property to get statusOverall as boolean
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("statusOverall")]
    public bool IsOverallValid => ServiceFeedMapper.GetBoolean(StatusOverall);

    [BsonElement("lastChecked")]
    public DateTime? LastChecked { get; set; }

    [BsonElement("lastError")]
    public string? LastError { get; set; }

    [BsonElement("responseTime")]
    public double? ResponseTimeMs { get; set; }

    [BsonElement("validationErrors")]
    public int? ValidationErrorCount { get; set; }

    [BsonElement("lastTested")]
    [BsonIgnoreIfNull]
    [JsonIgnore]
    public BsonValue? LastTested { get; set; }

    /// <summary>
    /// Helper property to get lastTested value as DateTime
    /// </summary>
    [BsonIgnore]
    [JsonPropertyName("lastTested")]
    public DateTime? LastTestedTime => ServiceFeedMapper.GetLastTestedTime(LastTested);

    /// <summary>
    /// Helper property to get lastTested url as string
    /// </summary>
    [BsonIgnore]
    public string? TestResultsUrl => ServiceFeedMapper.GetTestResultsUrl(LastTested);
}

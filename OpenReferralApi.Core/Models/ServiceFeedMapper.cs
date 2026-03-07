using MongoDB.Bson;

namespace OpenReferralApi.Core.Models;

public static class ServiceFeedMapper
{
    public static string GetUrl(ServiceFeed feed)
    {
        if (feed.Service != null && feed.Service.Contains("url"))
        {
            var urlValue = feed.Service["url"];
            if (urlValue != null && urlValue.IsString)
            {
                return urlValue.AsString;
            }
        }

        return feed.UrlField ?? string.Empty;
    }

    public static string? GetNameAsString(ServiceFeed feed)
    {
        return feed.Name?.ToString();
    }

    public static bool GetBoolean(BsonValue? value)
    {
        if (value == null) return false;
        if (value.IsBoolean) return value.AsBoolean;
        if (value.IsString) return value.AsString.Equals("true", StringComparison.OrdinalIgnoreCase);

        if (value.IsBsonDocument)
        {
            var doc = value.AsBsonDocument;
            if (!doc.Contains("value")) return false;

            var nestedValue = doc["value"];
            if (nestedValue.IsBoolean) return nestedValue.AsBoolean;
            if (nestedValue.IsString) return nestedValue.AsString.Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static DateTime? GetLastTestedTime(BsonValue? lastTested)
    {
        if (lastTested == null) return null;
        if (lastTested.IsValidDateTime) return lastTested.ToUniversalTime();

        if (!lastTested.IsBsonDocument) return null;

        var doc = lastTested.AsBsonDocument;
        if (doc.Contains("value") && doc["value"].IsValidDateTime)
        {
            return doc["value"].ToUniversalTime();
        }

        return null;
    }

    public static string? GetTestResultsUrl(BsonValue? lastTested)
    {
        if (lastTested == null || !lastTested.IsBsonDocument)
        {
            return null;
        }

        var doc = lastTested.AsBsonDocument;
        if (doc.Contains("url") && doc["url"].IsString)
        {
            return doc["url"].AsString;
        }

        return null;
    }
}
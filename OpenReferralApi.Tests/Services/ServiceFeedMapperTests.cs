using MongoDB.Bson;
using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class ServiceFeedMapperTests
{
    [Test]
    public void GetUrl_PrefersServiceUrl_FallsBackToUrlField()
    {
        var withServiceUrl = new ServiceFeed
        {
            Service = new BsonDocument { { "url", "https://from-service.example" } },
            UrlField = "https://from-url-field.example"
        };

        var withoutServiceUrl = new ServiceFeed
        {
            Service = new BsonDocument(),
            UrlField = "https://from-url-field.example"
        };

        Assert.That(ServiceFeedMapper.GetUrl(withServiceUrl), Is.EqualTo("https://from-service.example"));
        Assert.That(ServiceFeedMapper.GetUrl(withoutServiceUrl), Is.EqualTo("https://from-url-field.example"));
    }

    [Test]
    public void GetBoolean_HandlesBoolStringAndNestedValue()
    {
        Assert.That(ServiceFeedMapper.GetBoolean(new BsonBoolean(true)), Is.True);
        Assert.That(ServiceFeedMapper.GetBoolean(new BsonString("true")), Is.True);
        Assert.That(ServiceFeedMapper.GetBoolean(new BsonString("TRUE")), Is.True);
        Assert.That(ServiceFeedMapper.GetBoolean(new BsonString("false")), Is.False);

        var nested = new BsonDocument { { "value", "true" } };
        Assert.That(ServiceFeedMapper.GetBoolean(nested), Is.True);

        var nestedFalse = new BsonDocument { { "value", false } };
        Assert.That(ServiceFeedMapper.GetBoolean(nestedFalse), Is.False);
    }

    [Test]
    public void LastTestedMapping_HandlesScalarAndNestedShapes()
    {
        var now = DateTime.UtcNow;
        var scalar = new BsonDateTime(now);
        var nested = new BsonDocument
        {
            { "value", new BsonDateTime(now) },
            { "url", "/developers/dashboard/1" }
        };

        Assert.That(ServiceFeedMapper.GetLastTestedTime(scalar), Is.Not.Null);
        Assert.That(ServiceFeedMapper.GetLastTestedTime(nested), Is.Not.Null);
        Assert.That(ServiceFeedMapper.GetTestResultsUrl(nested), Is.EqualTo("/developers/dashboard/1"));
    }
}

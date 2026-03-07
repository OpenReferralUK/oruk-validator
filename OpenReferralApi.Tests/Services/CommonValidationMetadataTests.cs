using OpenReferralApi.Core.Models;

namespace OpenReferralApi.Tests.Services;

[TestFixture]
public class CommonValidationMetadataTests
{
    [Test]
    public void Timestamp_GetterAndSetter_UsesExpectedPrecedence()
    {
        var model = new CommonValidationMetadata();
        var t1 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        var t2 = new DateTime(2026, 2, 1, 12, 0, 0, DateTimeKind.Utc);

        model.Timestamp = t1;
        Assert.That(model.TestTimestamp, Is.EqualTo(t1));
        Assert.That(model.Timestamp, Is.EqualTo(t1));

        model.ValidationTimestamp = t2;
        Assert.That(model.Timestamp, Is.EqualTo(t1));

        var validationOnly = new CommonValidationMetadata
        {
            ValidationTimestamp = t2
        };

        Assert.That(validationOnly.Timestamp, Is.EqualTo(t2));
    }
}

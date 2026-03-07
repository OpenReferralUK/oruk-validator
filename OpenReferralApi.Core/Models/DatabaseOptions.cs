namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for MongoDB database connection
/// </summary>
public class DatabaseOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "Database";

    /// <summary>
    /// MongoDB connection string
    /// Example: mongodb://localhost:27017
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Name of the MongoDB database
    /// Default: oruk-v3
    /// </summary>
    public string DatabaseName { get; set; } = "oruk-v3";

    /// <summary>
    /// Name of the services collection in MongoDB
    /// Default: services
    /// </summary>
    public string ServicesCollection { get; set; } = "services";
}

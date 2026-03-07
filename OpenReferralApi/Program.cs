using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenReferralApi.Core.Models;
using OpenReferralApi.Core.Services;
using OpenReferralApi.HealthChecks;
using OpenReferralApi.Middleware;
using OpenReferralApi.Telemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables("ORUK_API_");

// Configure Serilog
builder.Host.UseSerilog((context, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration));

// Configure strongly-typed options
builder.Services.Configure<SpecificationOptions>(
    builder.Configuration.GetSection(SpecificationOptions.SectionName));

builder.Services.Configure<CacheOptions>(
    builder.Configuration.GetSection(CacheOptions.SectionName));

builder.Services.Configure<AuthenticationOptions>(
    builder.Configuration.GetSection(AuthenticationOptions.SectionName));

builder.Services.Configure<DatabaseOptions>(
    builder.Configuration.GetSection(DatabaseOptions.SectionName));

builder.Services.Configure<FeedValidationOptions>(
    builder.Configuration.GetSection(FeedValidationOptions.SectionName));

builder.Services.Configure<SecurityOptions>(
    builder.Configuration.GetSection(SecurityOptions.SectionName));

builder.Services.Configure<RateLimitingOptions>(
    builder.Configuration.GetSection(RateLimitingOptions.SectionName));

builder.Services.Configure<OpenTelemetryOptions>(
    builder.Configuration.GetSection(OpenTelemetryOptions.SectionName));

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

    options.SwaggerDoc("v1", new()
    {
        Title = "Open Referral UK API",
        Version = "v1",
        Description = "API for validating and monitoring Open Referral UK data feeds",
        Contact = new()
        {
            Name = "Open Referral UK",
            Url = new Uri("https://openreferraluk.org")
        }
    });
});

// CORS - Environment-specific origins
var securityOptions = builder.Configuration.GetSection(SecurityOptions.SectionName).Get<SecurityOptions>() ?? new SecurityOptions();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        if (securityOptions.AllowedCorsOrigins.Contains("*"))
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
        else
        {
            policy.WithOrigins(securityOptions.AllowedCorsOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

// Rate Limiting
var rateLimitingOptions = builder.Configuration.GetSection(RateLimitingOptions.SectionName).Get<RateLimitingOptions>() ?? new RateLimitingOptions();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("fixed", opt =>
    {
        opt.PermitLimit = rateLimitingOptions.PermitLimit;
        opt.Window = TimeSpan.FromSeconds(rateLimitingOptions.Window);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = rateLimitingOptions.QueueLimit;
    });
});

// Configure HTTP client with environment-based security settings
builder.Services.AddHttpClient(nameof(OpenApiValidationService), client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "OpenReferral-Validator/1.0");
    client.Timeout = TimeSpan.FromMinutes(2);
})
.ConfigurePrimaryHttpMessageHandler(sp =>
{
    var securityOpts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecurityOptions>>().Value;
    var handler = new HttpClientHandler();

    if (!securityOpts.ValidateSslCertificates)
    {
        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
    }

    handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;

    return handler;
});

builder.Services.AddHttpClient();
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });

// Response Caching
builder.Services.AddResponseCaching();
builder.Services.AddOutputCache(options =>
{
    options.AddBasePolicy(builder => builder.Cache());
    options.AddPolicy("MockEndpoints", builder =>
        builder.Expire(TimeSpan.FromMinutes(5)));
});

// Health Checks
var healthChecksBuilder = builder.Services.AddHealthChecks()
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "ready" });

var databaseOptions = builder.Configuration.GetSection(DatabaseOptions.SectionName).Get<DatabaseOptions>() ?? new DatabaseOptions();
if (!string.IsNullOrEmpty(databaseOptions.ConnectionString))
{
    // Register MongoDB client for health checks and feed validation
    builder.Services.AddSingleton<MongoDB.Driver.IMongoClient>(sp =>
    {
        return new MongoDB.Driver.MongoClient(databaseOptions.ConnectionString);
    });

    healthChecksBuilder.AddMongoDb(
        name: "mongodb",
        tags: new[] { "ready", "db" });

    // Feed validation services - only register if MongoDB is configured
    builder.Services.AddScoped<OpenReferralApi.Core.Services.IFeedValidationService, OpenReferralApi.Core.Services.FeedValidationService>();
    builder.Services.AddHostedService<OpenReferralApi.Services.FeedValidationBackgroundService>();
}
else
{
    // Register null implementation when MongoDB is not configured
    builder.Services.AddScoped<OpenReferralApi.Core.Services.IFeedValidationService, OpenReferralApi.Core.Services.NullFeedValidationService>();
}

healthChecksBuilder.AddCheck<FeedValidationHealthCheck>(
    "feed-validation",
    tags: new[] { "ready", "service" });

// Services
builder.Services.AddScoped<IPathParsingService, PathParsingService>();
builder.Services.AddSingleton<IRequestProcessingService, RequestProcessingService>();

// Schema Resolver Service - resolves $ref in remote schema files and creates JSchema objects
builder.Services.AddScoped<ISchemaResolverService, SchemaResolverService>();

builder.Services.AddScoped<IJsonValidatorService, JsonValidatorService>();
builder.Services.AddScoped<IOpenApiValidationService, OpenApiValidationService>();

builder.Services.AddScoped<IOpenApiDiscoveryService, OpenApiDiscoveryService>();
builder.Services.AddScoped<IOpenReferralUKValidationResponseMapper, OpenReferralUKValidationResponseMapper>();

// Configure Memory Cache with size limit from cache options
builder.Services.AddMemoryCache(options =>
{
    var cacheOpts = builder.Configuration.GetSection(CacheOptions.SectionName).Get<CacheOptions>() ?? new CacheOptions();
    options.SizeLimit = cacheOpts.MaxSizeMB * 1024 * 1024; // Convert MB to bytes
});

// Exception Handlers
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// OpenTelemetry Configuration
var otelOptions = builder.Configuration.GetSection(OpenTelemetryOptions.SectionName).Get<OpenTelemetryOptions>() ?? new OpenTelemetryOptions();
if (otelOptions.Enabled)
{
    var resourceBuilder = ResourceBuilder.CreateDefault()
        .AddService(
            serviceName: Instrumentation.ServiceName,
            serviceVersion: Instrumentation.ServiceVersion)
        .AddAttributes(new Dictionary<string, object>
        {
            ["deployment.environment"] = builder.Environment.EnvironmentName
        });

    builder.Services.AddOpenTelemetry()
        .WithMetrics(metrics =>
        {
            metrics
                .SetResourceBuilder(resourceBuilder)
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddMeter(Instrumentation.ServiceName);

            if (!string.IsNullOrEmpty(otelOptions.OtlpEndpoint))
            {
                metrics.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otelOptions.OtlpEndpoint);
                });
            }

            if (builder.Environment.IsDevelopment())
            {
                metrics.AddConsoleExporter();
            }
        })
        .WithTracing(tracing =>
        {
            tracing
                .SetResourceBuilder(resourceBuilder)
                .AddAspNetCoreInstrumentation(options =>
                {
                    options.RecordException = true;
                    options.Filter = httpContext =>
                    {
                        return !httpContext.Request.Path.StartsWithSegments("/health-check");
                    };
                })
                .AddHttpClientInstrumentation()
                .AddSource(Instrumentation.ActivitySource.Name);

            if (!string.IsNullOrEmpty(otelOptions.OtlpEndpoint))
            {
                tracing.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otelOptions.OtlpEndpoint);
                });
            }

            if (builder.Environment.IsDevelopment())
            {
                tracing.AddConsoleExporter();
            }
        });
}

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseExceptionHandler();

// Middleware
app.UseMiddleware<CorrelationIdMiddleware>();

// Enable Swagger in all environments
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Open Referral UK API v1");
    c.RoutePrefix = string.Empty;
    c.DisplayRequestDuration();
});

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// Health check endpoints
app.MapHealthChecks("/health-check", new HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecks("/health-check/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

// Overall service health for CI/deploy checks
app.MapHealthChecks("/health-check/overall", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecks("/health-check/live", new HealthCheckOptions
{
    Predicate = _ => false,
    ResponseWriter = async (context, _) =>
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            status = "Healthy",
            timestamp = DateTime.UtcNow
        }));
    }
});

app.UseRouting();
app.UseSerilogRequestLogging();
app.UseCors();
app.UseHttpsRedirection();
app.UseResponseCaching();
app.UseOutputCache();
app.UseRateLimiter();

app.MapControllerRoute(name: "default", pattern: "{controller}/{action=Index}/{id?}");

app.Run();

// Ensure logs are flushed on shutdown
Log.CloseAndFlush();

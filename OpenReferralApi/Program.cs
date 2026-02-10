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

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddEnvironmentVariables("ORUK_API_");

// Configure strongly-typed options
builder.Services.Configure<SpecificationOptions>(
    builder.Configuration.GetSection(SpecificationOptions.SectionName));

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
var allowedOrigins = builder.Configuration.GetSection("Security:AllowedCorsOrigins").Get<string[]>()
                     ?? new[] { "*" };

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        if (allowedOrigins.Contains("*"))
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
        else
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

// Rate Limiting
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("fixed", opt =>
    {
        opt.PermitLimit = builder.Configuration.GetValue<int>("RateLimiting:PermitLimit", 100);
        opt.Window = TimeSpan.FromSeconds(builder.Configuration.GetValue<int>("RateLimiting:Window", 60));
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = builder.Configuration.GetValue<int>("RateLimiting:QueueLimit", 0);
    });
});

// Configure HTTP client with environment-based security settings
var validateSslCertificates = builder.Configuration.GetValue<bool>("Security:ValidateSslCertificates", true);

builder.Services.AddHttpClient(nameof(OpenApiValidationService), client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "OpenReferral-Validator/1.0");
    client.Timeout = TimeSpan.FromMinutes(2);
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();

    if (!validateSslCertificates)
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

var mongoConnectionString = builder.Configuration.GetValue<string>("Database:ConnectionString");
if (!string.IsNullOrEmpty(mongoConnectionString))
{
    // Register MongoDB client for health checks and feed validation
    builder.Services.AddSingleton<MongoDB.Driver.IMongoClient>(sp =>
    {
        return new MongoDB.Driver.MongoClient(mongoConnectionString);
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
builder.Services.AddScoped<IOpenApiValidationService>(provider =>
{
    var logger = provider.GetRequiredService<ILogger<OpenApiValidationService>>();
    var httpClientFactory = provider.GetRequiredService<IHttpClientFactory>();
    var httpClient = httpClientFactory.CreateClient(nameof(OpenApiValidationService));
    var jsonValidatorService = provider.GetRequiredService<IJsonValidatorService>();
    var schemaResolverService = provider.GetRequiredService<ISchemaResolverService>();
    var discoveryService = provider.GetRequiredService<IOpenApiDiscoveryService>();
    return new OpenApiValidationService(logger, httpClient, jsonValidatorService, schemaResolverService, discoveryService);
});

builder.Services.AddScoped<IOpenApiDiscoveryService, OpenApiDiscoveryService>();
builder.Services.AddScoped<IOpenApiToValidationResponseMapper, OpenApiToValidationResponseMapper>();

builder.Services.AddMemoryCache();

// Exception Handlers
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

// OpenTelemetry Configuration
var otelEnabled = builder.Configuration.GetValue<bool>("OpenTelemetry:Enabled", false);
if (otelEnabled)
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

            var otlpEndpoint = builder.Configuration.GetValue<string>("OpenTelemetry:OtlpEndpoint");
            if (!string.IsNullOrEmpty(otlpEndpoint))
            {
                metrics.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otlpEndpoint);
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

            var otlpEndpoint = builder.Configuration.GetValue<string>("OpenTelemetry:OtlpEndpoint");
            if (!string.IsNullOrEmpty(otlpEndpoint))
            {
                tracing.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otlpEndpoint);
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
app.UseCors();
app.UseHttpsRedirection();
app.UseResponseCaching();
app.UseOutputCache();
app.UseRateLimiter();

app.MapControllerRoute(name: "default", pattern: "{controller}/{action=Index}/{id?}");

app.Run();

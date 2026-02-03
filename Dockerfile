# Build arguments for versioning and metadata
ARG BUILD_VERSION=1.0.0
ARG BUILD_DATE
ARG VCS_REF

# Base runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_VERSION
WORKDIR /src

# Copy only project files first for better layer caching
COPY ["OpenReferralApi/OpenReferralApi.csproj", "OpenReferralApi/"]
COPY ["OpenReferralApi.Core/OpenReferralApi.Core.csproj", "OpenReferralApi.Core/"]
COPY ["OpenReferralApi.Tests/OpenReferralApi.Tests.csproj", "OpenReferralApi.Tests/"]

# Restore dependencies (cached unless project files change)
RUN dotnet restore "OpenReferralApi/OpenReferralApi.csproj"

# Copy all source code
COPY . .

# Build the application
WORKDIR "/src/OpenReferralApi"
RUN dotnet build "OpenReferralApi.csproj" -c Release -o /app/build /p:Version=${BUILD_VERSION}

# Test stage (optional, can be skipped in production builds)
FROM build AS test
WORKDIR /src
RUN dotnet test "OpenReferralApi.Tests/OpenReferralApi.Tests.csproj" --configuration Release --no-build --verbosity normal

# Publish stage
FROM build AS publish
ARG BUILD_VERSION
RUN dotnet publish "OpenReferralApi.csproj" -c Release -o /app/publish /p:Version=${BUILD_VERSION} /p:UseAppHost=false

# Final stage
FROM base AS final
ARG BUILD_VERSION
ARG BUILD_DATE
ARG VCS_REF

# Add labels for image metadata
LABEL org.opencontainers.image.title="Open Referral UK API"
LABEL org.opencontainers.image.description="API for validating and monitoring Open Referral UK data feeds"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.vendor="TpX Impact"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"

WORKDIR /app

# Copy published files
COPY --from=publish /app/publish .

# Copy schemas and mocks
COPY --from=publish /src/OpenReferralApi/Schemas ./Schemas
COPY --from=publish /src/OpenReferralApi/Mocks ./Mocks

# Set ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:${PORT:-80}/health-check/live || exit 1

# Run the application
# Note: Using shell form (not JSON array) to allow runtime $PORT variable expansion for Heroku.
# This triggers a linter warning about signal handling, but is necessary for dynamic port binding.
CMD ASPNETCORE_URLS=http://*:$PORT dotnet OpenReferralApi.dll

# For local development use ENTRYPOINT & comment out CMD line
# ENTRYPOINT ["dotnet", "OpenReferralApi.dll"]

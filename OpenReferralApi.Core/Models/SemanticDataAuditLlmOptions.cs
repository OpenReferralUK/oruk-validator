namespace OpenReferralApi.Core.Models;

/// <summary>
/// Configuration options for LLM-backed semantic auditing.
/// </summary>
public class SemanticDataAuditLlmOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "SemanticDataAudit:Llm";

    /// <summary>
    /// Whether LLM scoring is enabled.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// LLM provider. Supported values: AzureOpenAI, OpenAI.
    /// </summary>
    public string Provider { get; set; } = "AzureOpenAI";

    /// <summary>
    /// Endpoint URL. For Azure OpenAI, this is the resource endpoint.
    /// For OpenAI-compatible APIs, this can be a full chat completions URL.
    /// </summary>
    public string Endpoint { get; set; } = string.Empty;

    /// <summary>
    /// API key used for LLM authentication.
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// Deployment name (Azure OpenAI) or model name (OpenAI).
    /// </summary>
    public string DeploymentOrModel { get; set; } = string.Empty;

    /// <summary>
    /// API version for Azure OpenAI.
    /// </summary>
    public string ApiVersion { get; set; } = "2024-10-21";

    /// <summary>
    /// Sampling temperature.
    /// </summary>
    public double Temperature { get; set; } = 0.0;

    /// <summary>
    /// Max output tokens from the LLM.
    /// </summary>
    public int MaxTokens { get; set; } = 300;
}

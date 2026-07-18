using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Certael.Installer;

public enum CertaelEngine { None, Godot, Unity, Unreal, Native }
public enum CertaelServerRuntime { DotNet, Node, Native, Custom }
public enum CertaelDeploymentMode { Development, Staging, Production }
public enum CertaelIdentityProvider { Auth0, Keycloak, Entra, GenericOidc, Development }
public enum CertaelProvider { Steam, EpicOnlineServices, PlayFab, Agones, Custom }

public sealed record CertaelProjectConfiguration
{
    public uint SchemaVersion { get; init; } = 1;
    public required string ProjectName { get; init; }
    public required CertaelEngine Engine { get; init; }
    public required CertaelServerRuntime ServerRuntime { get; init; }
    public required CertaelDeploymentMode DeploymentMode { get; init; }
    public required CertaelIdentityProvider IdentityProvider { get; init; }
    public List<CertaelProvider> Providers { get; init; } = [];
    public List<string> Components { get; init; } =
        ["core-api", "event-worker", "analytics-worker", "console", "deployment", "certaelctl"];
    public string? TenantId { get; init; }
    public string? EnvironmentId { get; init; }

    public void Validate()
    {
        if (SchemaVersion != 1) throw new ConfigurationException("Unsupported project configuration schema.");
        ValidateIdentifier(ProjectName, "Project name", 128, allowSpace: true);
        if (!Enum.IsDefined(Engine) || !Enum.IsDefined(ServerRuntime)
            || !Enum.IsDefined(DeploymentMode) || !Enum.IsDefined(IdentityProvider))
            throw new ConfigurationException("Project configuration contains an unknown selection.");
        if (DeploymentMode == CertaelDeploymentMode.Production
            && IdentityProvider == CertaelIdentityProvider.Development)
            throw new ConfigurationException("Development identity cannot be used in production.");
        if (Providers.Count > 16 || Providers.Any(provider => !Enum.IsDefined(provider)))
            throw new ConfigurationException("Provider selection is invalid.");
        if (Components.Count is 0 or > 64 || Components.Distinct(StringComparer.Ordinal).Count() != Components.Count)
            throw new ConfigurationException("Component selection is invalid or contains duplicates.");
        foreach (string component in Components)
            ValidateIdentifier(component, "Component", 96, allowSpace: false);
        if (TenantId is not null) ValidateIdentifier(TenantId, "Tenant ID", 128, allowSpace: false);
        if (EnvironmentId is not null) ValidateIdentifier(EnvironmentId, "Environment ID", 128, allowSpace: false);
    }

    public IReadOnlyList<string> RequiredComponents()
    {
        Validate();
        var result = new HashSet<string>(Components, StringComparer.Ordinal);
        string? engineComponent = Engine switch
        {
            CertaelEngine.Godot => "godot-adapter",
            CertaelEngine.Unity => "unity-adapter",
            CertaelEngine.Unreal => "unreal-adapter",
            CertaelEngine.Native => "native-runtime",
            _ => null
        };
        if (engineComponent is not null) result.Add(engineComponent);

        string? serverComponent = ServerRuntime switch
        {
            CertaelServerRuntime.DotNet => "server-sdk-dotnet",
            CertaelServerRuntime.Node => "server-sdk-typescript",
            CertaelServerRuntime.Native => "server-sdk-native",
            _ => null
        };
        if (serverComponent is not null) result.Add(serverComponent);

        foreach (CertaelProvider provider in Providers)
        {
            string? component = provider switch
            {
                CertaelProvider.Steam => "integration-steam",
                CertaelProvider.EpicOnlineServices => "integration-eos",
                CertaelProvider.PlayFab => "integration-playfab",
                CertaelProvider.Agones => "integration-agones",
                _ => null
            };
            if (component is not null) result.Add(component);
        }
        return result.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static void ValidateIdentifier(string value, string label, int maximum, bool allowSpace)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-' || allowSpace && character == ' ')))
            throw new ConfigurationException($"{label} is invalid.");
    }
}

public static class CertaelProjectConfigurationCodec
{
    private static readonly ISerializer Serializer = new SerializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static string Encode(CertaelProjectConfiguration configuration)
    {
        configuration.Validate();
        return Serializer.Serialize(configuration);
    }

    public static CertaelProjectConfiguration Decode(string yaml)
    {
        if (yaml.Length > 256 * 1024) throw new ConfigurationException("Project configuration is too large.");
        CertaelProjectConfiguration configuration;
        try { configuration = Deserializer.Deserialize<CertaelProjectConfiguration>(yaml); }
        catch (Exception exception) when (exception is YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            throw new ConfigurationException("Project configuration YAML is invalid.", exception);
        }
        if (configuration is null) throw new ConfigurationException("Project configuration is empty.");
        configuration.Validate();
        return configuration;
    }
}

public sealed class ConfigurationException(string message, Exception? inner = null)
    : Exception(message, inner);

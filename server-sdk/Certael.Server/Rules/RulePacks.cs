using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Certael.Server.Rules;

public enum RuleDataProvenance
{
    ClientClaim,
    ClientTelemetry,
    ClientIntegrityObservation,
    PlatformAttestation,
    GameServerObservation,
    AuthoritativeState
}

public sealed record RulePackDocument(
    string PackId,
    string Version,
    string GameId,
    string EnvironmentId,
    uint ProtocolMinimum,
    uint ProtocolMaximum,
    IReadOnlyList<RulePackRule> Rules);

public sealed record RulePackRule(
    string RuleId,
    string Version,
    RuleDataProvenance Provenance,
    string ActionType,
    string PublicFailureReason,
    int MaximumRiskContribution,
    RuleExpression Expression);

public sealed record SignedRulePack(
    RulePackDocument Document,
    byte[] CanonicalDocument,
    byte[] Digest,
    byte[] Signature,
    string SigningKeyId);

public sealed class RulePackCompiler(ECDsa signingKey, string signingKeyId)
{
    private static readonly Regex Identifier = new(
        "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
        TimeSpan.FromMilliseconds(50));

    public SignedRulePack CompileAndSign(RulePackDocument document)
    {
        Validate(document);
        byte[] canonical = CanonicalRulePackSerializer.Serialize(document);
        byte[] digest = SHA256.HashData(canonical);
        byte[] signature = signingKey.SignHash(digest);
        return new SignedRulePack(document, canonical, digest, signature, signingKeyId);
    }

    public static void Validate(RulePackDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        RequireIdentifier(document.PackId, nameof(document.PackId));
        RequireIdentifier(document.GameId, nameof(document.GameId));
        RequireIdentifier(document.EnvironmentId, nameof(document.EnvironmentId));
        if (!Version.TryParse(document.Version, out Version? parsed) || parsed.ToString() != document.Version)
            throw new RulePackValidationException("Version must be canonical semantic numeric notation.");
        if (document.ProtocolMinimum == 0 || document.ProtocolMaximum < document.ProtocolMinimum)
            throw new RulePackValidationException("Protocol range is invalid.");
        if (document.Rules.Count is < 1 or > 10_000)
            throw new RulePackValidationException("Rule count is invalid.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (RulePackRule rule in document.Rules)
        {
            RequireIdentifier(rule.RuleId, nameof(rule.RuleId));
            RequireIdentifier(rule.ActionType, nameof(rule.ActionType));
            if (!ids.Add(rule.RuleId)) throw new RulePackValidationException("Rule IDs must be unique.");
            if (!Version.TryParse(rule.Version, out _)) throw new RulePackValidationException("Rule version is invalid.");
            if (rule.MaximumRiskContribution is < 0 or > 100)
                throw new RulePackValidationException("Risk contribution is invalid.");
            if (string.IsNullOrWhiteSpace(rule.PublicFailureReason) || rule.PublicFailureReason.Length > 64
                || !rule.PublicFailureReason.All(static value => char.IsAsciiLetterOrDigit(value) || value == '_'))
                throw new RulePackValidationException("Public failure reason is invalid.");
            if (rule.Provenance is RuleDataProvenance.ClientTelemetry
                or RuleDataProvenance.ClientIntegrityObservation
                or RuleDataProvenance.PlatformAttestation
                && rule.MaximumRiskContribution > 30)
                throw new RulePackValidationException("Untrusted or environmental signals are capped at risk 30.");
        }
    }

    private static void RequireIdentifier(string value, string name)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128 || !Identifier.IsMatch(value))
            throw new RulePackValidationException($"{name} is invalid.");
    }
}

public sealed class RulePackVerifier(IReadOnlyDictionary<string, ECDsa> trustedKeys)
{
    public bool Verify(SignedRulePack pack)
    {
        if (!trustedKeys.TryGetValue(pack.SigningKeyId, out ECDsa? key)) return false;
        byte[] canonical;
        try { RulePackCompiler.Validate(pack.Document); canonical = CanonicalRulePackSerializer.Serialize(pack.Document); }
        catch (RulePackValidationException) { return false; }
        byte[] digest = SHA256.HashData(canonical);
        return CryptographicOperations.FixedTimeEquals(canonical, pack.CanonicalDocument)
            && CryptographicOperations.FixedTimeEquals(digest, pack.Digest)
            && key.VerifyHash(digest, pack.Signature);
    }
}

internal static class CanonicalRulePackSerializer
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new RuleExpressionJsonConverter() }
    };

    public static byte[] Serialize(RulePackDocument document)
    {
        RulePackDocument ordered = document with
        {
            Rules = document.Rules.OrderBy(rule => rule.RuleId, StringComparer.Ordinal).ToArray()
        };
        return JsonSerializer.SerializeToUtf8Bytes(ordered, Json);
    }
}

public sealed class RulePackValidationException(string message) : Exception(message);

internal sealed class RuleExpressionJsonConverter : System.Text.Json.Serialization.JsonConverter<RuleExpression>
{
    public override RuleExpression Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("Rule pack deserialization uses the dedicated parser.");

    public override void Write(Utf8JsonWriter writer, RuleExpression value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        switch (value)
        {
            case ConstantExpression constant:
                writer.WriteString("kind", "constant"); writer.WritePropertyName("value");
                JsonSerializer.Serialize(writer, constant.Value, options); break;
            case FieldExpression field:
                writer.WriteString("kind", "field"); writer.WriteString("source", field.Source.ToString());
                writer.WriteString("path", field.Path); break;
            case CompareExpression compare:
                writer.WriteString("kind", "compare"); writer.WriteString("operator", compare.Operator.ToString());
                writer.WritePropertyName("left"); Write(writer, compare.Left, options);
                writer.WritePropertyName("right"); Write(writer, compare.Right, options); break;
            case LogicalExpression logical:
                writer.WriteString("kind", "logical"); writer.WriteString("operator", logical.Operator.ToString());
                writer.WritePropertyName("operands"); writer.WriteStartArray();
                foreach (RuleExpression operand in logical.Operands) Write(writer, operand, options);
                writer.WriteEndArray(); break;
            case NotExpression not:
                writer.WriteString("kind", "not"); writer.WritePropertyName("operand"); Write(writer, not.Operand, options); break;
            default: throw new RulePackValidationException("Unsupported rule expression.");
        }
        writer.WriteEndObject();
    }
}

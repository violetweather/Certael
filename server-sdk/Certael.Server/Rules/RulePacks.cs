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
    string TenantId,
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
        byte[] canonical = RulePackCanonicalCodec.Serialize(document);
        byte[] digest = SHA256.HashData(canonical);
        byte[] signature = signingKey.SignHash(digest);
        return new SignedRulePack(document, canonical, digest, signature, signingKeyId);
    }

    public static void Validate(RulePackDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        RequireIdentifier(document.TenantId, nameof(document.TenantId));
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
            ValidateExpression(rule.Expression);
        }
    }

    private static void ValidateExpression(RuleExpression root)
    {
        var pending = new Stack<(RuleExpression Expression, int Depth)>();
        pending.Push((root ?? throw new RulePackValidationException("Rule expression is missing."), 1));
        int operations = 0;
        while (pending.TryPop(out (RuleExpression Expression, int Depth) item))
        {
            if (++operations > 256 || item.Depth > 32)
                throw new RulePackValidationException("Rule expression exceeds its operation or depth limit.");
            switch (item.Expression)
            {
                case ConstantExpression constant when constant.Value is null or string or bool
                    or byte or sbyte or short or ushort or int or uint or long or ulong or decimal:
                    if (constant.Value is string text && text.Length > 4096)
                        throw new RulePackValidationException("Rule constant is too long.");
                    break;
                case FieldExpression field:
                    string[] segments = field.Path.Split('.', StringSplitOptions.RemoveEmptyEntries);
                    if (segments.Length is < 1 or > 16 || segments.Any(segment => segment.Length is < 1 or > 64
                        || !segment.All(character => char.IsAsciiLetterOrDigit(character) || character == '_')
                        || !(char.IsAsciiLetter(segment[0]) || segment[0] == '_')))
                        throw new RulePackValidationException("Rule field path is invalid.");
                    break;
                case CompareExpression compare:
                    pending.Push((compare.Right, item.Depth + 1));
                    pending.Push((compare.Left, item.Depth + 1));
                    break;
                case LogicalExpression logical when logical.Operands.Count is >= 1 and <= 64:
                    foreach (RuleExpression operand in logical.Operands)
                        pending.Push((operand, item.Depth + 1));
                    break;
                case NotExpression not:
                    pending.Push((not.Operand, item.Depth + 1));
                    break;
                default:
                    throw new RulePackValidationException("Unsupported or invalid rule expression.");
            }
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
        try { RulePackCompiler.Validate(pack.Document); canonical = RulePackCanonicalCodec.Serialize(pack.Document); }
        catch (RulePackValidationException) { return false; }
        byte[] digest = SHA256.HashData(canonical);
        return CryptographicOperations.FixedTimeEquals(canonical, pack.CanonicalDocument)
            && CryptographicOperations.FixedTimeEquals(digest, pack.Digest)
            && key.VerifyHash(digest, pack.Signature);
    }
}

public static class RulePackCanonicalCodec
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

    public static RulePackDocument Deserialize(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < 1 or > 1_048_576)
            throw new RulePackValidationException("Canonical rule pack size is invalid.");
        RulePackDocument document;
        try
        {
            document = JsonSerializer.Deserialize<RulePackDocument>(canonical, Json)
                ?? throw new RulePackValidationException("Canonical rule pack is empty.");
        }
        catch (JsonException error)
        {
            throw new RulePackValidationException($"Canonical rule pack is invalid: {error.Message}");
        }
        RulePackCompiler.Validate(document);
        if (!CryptographicOperations.FixedTimeEquals(Serialize(document), canonical))
            throw new RulePackValidationException("Rule pack encoding is not canonical.");
        return document;
    }
}

public sealed class RulePackValidationException(string message) : Exception(message);

internal sealed class RuleExpressionJsonConverter : System.Text.Json.Serialization.JsonConverter<RuleExpression>
{
    public override RuleExpression Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using JsonDocument document = JsonDocument.ParseValue(ref reader);
        int operations = 0;
        return Parse(document.RootElement, 1, ref operations);
    }

    private static RuleExpression Parse(JsonElement element, int depth, ref int operations)
    {
        if (++operations > 256 || depth > 32 || element.ValueKind != JsonValueKind.Object)
            throw new JsonException("Rule expression exceeds structural limits.");
        string kind = RequiredString(element, "kind");
        return kind switch
        {
            "constant" => Constant(element),
            "field" => Field(element),
            "compare" => Compare(element, depth, ref operations),
            "logical" => Logical(element, depth, ref operations),
            "not" => Not(element, depth, ref operations),
            _ => throw new JsonException("Unknown rule expression kind.")
        };
    }

    private static RuleExpression Constant(JsonElement element)
    {
        ExactProperties(element, "kind", "value");
        JsonElement value = Required(element, "value");
        object? parsed = value.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number when value.TryGetInt64(out long signed) => signed,
            JsonValueKind.Number when value.TryGetUInt64(out ulong unsigned) => unsigned,
            JsonValueKind.Number when value.TryGetDecimal(out decimal number) => number,
            _ => throw new JsonException("Unsupported rule constant.")
        };
        return new ConstantExpression(parsed);
    }

    private static RuleExpression Field(JsonElement element)
    {
        ExactProperties(element, "kind", "source", "path");
        if (!Enum.TryParse(RequiredString(element, "source"), false, out RuleDataSource source))
            throw new JsonException("Unknown rule field source.");
        return new FieldExpression(RequiredString(element, "path"), source);
    }

    private static RuleExpression Compare(JsonElement element, int depth, ref int operations)
    {
        ExactProperties(element, "kind", "operator", "left", "right");
        if (!Enum.TryParse(RequiredString(element, "operator"), false, out ComparisonOperator operation))
            throw new JsonException("Unknown comparison operator.");
        RuleExpression left = Parse(Required(element, "left"), depth + 1, ref operations);
        RuleExpression right = Parse(Required(element, "right"), depth + 1, ref operations);
        return new CompareExpression(operation, left, right);
    }

    private static RuleExpression Logical(JsonElement element, int depth, ref int operations)
    {
        ExactProperties(element, "kind", "operator", "operands");
        if (!Enum.TryParse(RequiredString(element, "operator"), false, out LogicalOperator operation))
            throw new JsonException("Unknown logical operator.");
        JsonElement operands = Required(element, "operands");
        if (operands.ValueKind != JsonValueKind.Array || operands.GetArrayLength() is < 1 or > 64)
            throw new JsonException("Logical operand count is invalid.");
        var values = new List<RuleExpression>(operands.GetArrayLength());
        foreach (JsonElement operand in operands.EnumerateArray())
            values.Add(Parse(operand, depth + 1, ref operations));
        return new LogicalExpression(operation, values);
    }

    private static RuleExpression Not(JsonElement element, int depth, ref int operations)
    {
        ExactProperties(element, "kind", "operand");
        return new NotExpression(Parse(Required(element, "operand"), depth + 1, ref operations));
    }

    private static JsonElement Required(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) ? value
            : throw new JsonException($"Missing rule expression property '{name}'.");

    private static string RequiredString(JsonElement element, string name) =>
        Required(element, name).ValueKind == JsonValueKind.String
            ? Required(element, name).GetString() ?? throw new JsonException("Null string is invalid.")
            : throw new JsonException($"Rule expression property '{name}' must be a string.");

    private static void ExactProperties(JsonElement element, params string[] names)
    {
        var allowed = new HashSet<string>(names, StringComparer.Ordinal);
        int count = 0;
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!allowed.Remove(property.Name)) throw new JsonException("Unknown or duplicate rule expression property.");
            count++;
        }
        if (count != names.Length || allowed.Count != 0) throw new JsonException("Rule expression property set is incomplete.");
    }

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

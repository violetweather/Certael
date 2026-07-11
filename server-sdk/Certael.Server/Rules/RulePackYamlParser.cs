using System.Globalization;
using YamlDotNet.RepresentationModel;

namespace Certael.Server.Rules;

public sealed class RulePackYamlParser(
    int maximumBytes = 1_048_576,
    int maximumNodes = 50_000,
    int maximumDepth = 32,
    int maximumScalarLength = 4096)
{
    public RulePackDocument Parse(string yaml)
    {
        ArgumentNullException.ThrowIfNull(yaml);
        if (System.Text.Encoding.UTF8.GetByteCount(yaml) > maximumBytes)
            throw new RulePackValidationException("Rule pack exceeds the size limit.");
        var stream = new YamlStream();
        try { stream.Load(new StringReader(yaml)); }
        catch (YamlDotNet.Core.YamlException error)
        { throw new RulePackValidationException($"Invalid YAML at line {error.Start.Line}."); }
        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root)
            throw new RulePackValidationException("A rule pack must contain one mapping document.");
        int nodes = 0;
        ValidateStructure(root, 0, ref nodes);
        RejectUnknown(root, "apiVersion", "kind", "metadata", "compatibility", "actions", "rules");
        if (Scalar(root, "apiVersion") != "certael.dev/v1" || Scalar(root, "kind") != "RulePack")
            throw new RulePackValidationException("Unsupported rule-pack API version or kind.");

        YamlMappingNode metadata = Mapping(root, "metadata");
        YamlMappingNode compatibility = Mapping(root, "compatibility");
        RejectUnknown(metadata, "id", "version", "gameId", "environmentId");
        RejectUnknown(compatibility, "protocolMinimum", "protocolMaximum");
        YamlSequenceNode rules = Sequence(root, "rules");
        RulePackRule[] parsedRules = rules.Children.Select(ParseRule).ToArray();
        return new RulePackDocument(
            Scalar(metadata, "id"), Scalar(metadata, "version"), Scalar(metadata, "gameId"),
            Scalar(metadata, "environmentId"), UInt(compatibility, "protocolMinimum"),
            UInt(compatibility, "protocolMaximum"), parsedRules);
    }

    private RulePackRule ParseRule(YamlNode node)
    {
        YamlMappingNode rule = RequireMapping(node, "A rule must be a mapping.");
        RejectUnknown(rule, "id", "version", "provenance", "actionType", "publicFailureReason",
            "maximumRiskContribution", "expression");
        if (!Enum.TryParse(Scalar(rule, "provenance"), false, out RuleDataProvenance provenance))
            throw new RulePackValidationException("Rule provenance is invalid.");
        return new RulePackRule(Scalar(rule, "id"), Scalar(rule, "version"), provenance,
            Scalar(rule, "actionType"), Scalar(rule, "publicFailureReason"),
            checked((int)UInt(rule, "maximumRiskContribution")), ParseExpression(Required(rule, "expression")));
    }

    private RuleExpression ParseExpression(YamlNode node)
    {
        YamlMappingNode expression = RequireMapping(node, "An expression must be a mapping.");
        if (expression.Children.Count != 1)
            throw new RulePackValidationException("An expression must contain exactly one operator.");
        KeyValuePair<YamlNode, YamlNode> entry = expression.Children.Single();
        string kind = RequireScalar(entry.Key, "Expression operator must be a scalar.").Value ?? "";
        return kind switch
        {
            "constant" => new ConstantExpression(ParseConstant(entry.Value)),
            "field" => ParseField(entry.Value),
            "compare" => ParseCompare(entry.Value),
            "logical" => ParseLogical(entry.Value),
            "not" => new NotExpression(ParseExpression(entry.Value)),
            _ => throw new RulePackValidationException("Unsupported expression operator.")
        };
    }

    private FieldExpression ParseField(YamlNode node)
    {
        YamlMappingNode field = RequireMapping(node, "A field must be a mapping.");
        RejectUnknown(field, "source", "path");
        if (!Enum.TryParse(Scalar(field, "source"), false, out RuleDataSource source))
            throw new RulePackValidationException("Field source is invalid.");
        return new FieldExpression(Scalar(field, "path"), source);
    }

    private CompareExpression ParseCompare(YamlNode node)
    {
        YamlMappingNode compare = RequireMapping(node, "A comparison must be a mapping.");
        RejectUnknown(compare, "operator", "left", "right");
        if (!Enum.TryParse(Scalar(compare, "operator"), false, out ComparisonOperator operation))
            throw new RulePackValidationException("Comparison operator is invalid.");
        return new CompareExpression(operation, ParseExpression(Required(compare, "left")),
            ParseExpression(Required(compare, "right")));
    }

    private LogicalExpression ParseLogical(YamlNode node)
    {
        YamlMappingNode logical = RequireMapping(node, "A logical expression must be a mapping.");
        RejectUnknown(logical, "operator", "operands");
        if (!Enum.TryParse(Scalar(logical, "operator"), false, out LogicalOperator operation))
            throw new RulePackValidationException("Logical operator is invalid.");
        return new LogicalExpression(operation, Sequence(logical, "operands").Children.Select(ParseExpression).ToArray());
    }

    private static object? ParseConstant(YamlNode node)
    {
        string value = RequireScalar(node, "A constant must be scalar.").Value ?? "";
        if (value == "null") return null;
        if (bool.TryParse(value, out bool boolean)) return boolean;
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long integer)) return integer;
        if (decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out decimal number)) return number;
        return value;
    }

    private void ValidateStructure(YamlNode node, int depth, ref int nodes)
    {
        if (depth > maximumDepth || ++nodes > maximumNodes)
            throw new RulePackValidationException("Rule pack structural limits exceeded.");
        switch (node)
        {
            case YamlScalarNode scalar when (scalar.Value?.Length ?? 0) > maximumScalarLength:
                throw new RulePackValidationException("Rule pack scalar exceeds the length limit.");
            case YamlMappingNode mapping:
                foreach (var child in mapping.Children)
                { ValidateStructure(child.Key, depth + 1, ref nodes); ValidateStructure(child.Value, depth + 1, ref nodes); }
                break;
            case YamlSequenceNode sequence:
                foreach (YamlNode child in sequence.Children) ValidateStructure(child, depth + 1, ref nodes);
                break;
            case YamlScalarNode: break;
            default: throw new RulePackValidationException("Aliases and custom YAML nodes are prohibited.");
        }
    }

    private static void RejectUnknown(YamlMappingNode mapping, params string[] allowed)
    {
        var set = allowed.ToHashSet(StringComparer.Ordinal);
        foreach (YamlNode key in mapping.Children.Keys)
            if (!set.Contains(RequireScalar(key, "Mapping keys must be scalar.").Value ?? ""))
                throw new RulePackValidationException("Rule pack contains an unknown field.");
    }

    private static YamlNode Required(YamlMappingNode mapping, string key) =>
        mapping.Children.TryGetValue(new YamlScalarNode(key), out YamlNode? value)
            ? value : throw new RulePackValidationException($"Required field '{key}' is missing.");
    private static string Scalar(YamlMappingNode mapping, string key) =>
        RequireScalar(Required(mapping, key), $"Field '{key}' must be scalar.").Value ?? "";
    private static uint UInt(YamlMappingNode mapping, string key) =>
        uint.TryParse(Scalar(mapping, key), NumberStyles.None, CultureInfo.InvariantCulture, out uint value)
            ? value : throw new RulePackValidationException($"Field '{key}' must be an unsigned integer.");
    private static YamlMappingNode Mapping(YamlMappingNode mapping, string key) =>
        RequireMapping(Required(mapping, key), $"Field '{key}' must be a mapping.");
    private static YamlSequenceNode Sequence(YamlMappingNode mapping, string key) =>
        Required(mapping, key) as YamlSequenceNode
            ?? throw new RulePackValidationException($"Field '{key}' must be a sequence.");
    private static YamlMappingNode RequireMapping(YamlNode node, string message) =>
        node as YamlMappingNode ?? throw new RulePackValidationException(message);
    private static YamlScalarNode RequireScalar(YamlNode node, string message) =>
        node as YamlScalarNode ?? throw new RulePackValidationException(message);
}

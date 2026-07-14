using System.Collections;
using System.Globalization;

namespace Certael.Server.Rules;

public abstract record RuleExpression;
public sealed record ConstantExpression(object? Value) : RuleExpression;
public sealed record FieldExpression(string Path, RuleDataSource Source) : RuleExpression;
public sealed record CompareExpression(ComparisonOperator Operator, RuleExpression Left, RuleExpression Right) : RuleExpression;
public sealed record LogicalExpression(LogicalOperator Operator, IReadOnlyList<RuleExpression> Operands) : RuleExpression;
public sealed record NotExpression(RuleExpression Operand) : RuleExpression;

public enum RuleDataSource { Request, AuthoritativeState }
public enum ComparisonOperator { Equal, NotEqual, Less, LessOrEqual, Greater, GreaterOrEqual }
public enum LogicalOperator { All, Any }

public sealed record RuleEvaluationContext(
    IReadOnlyDictionary<string, object?> Request,
    IReadOnlyDictionary<string, object?> AuthoritativeState);

public sealed class DeclarativeRuleEvaluator(int maximumOperations = 256, int maximumPathDepth = 16)
{
    public bool Evaluate(RuleExpression expression, RuleEvaluationContext context)
    {
        if (maximumOperations is < 1 or > 10_000 || maximumPathDepth is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(maximumOperations));
        int operations = maximumOperations;
        object? value = EvaluateValue(expression, context, ref operations);
        return value is bool result
            ? result
            : throw new RuleEvaluationException("A rule root must produce a boolean value.");
    }

    private object? EvaluateValue(RuleExpression expression, RuleEvaluationContext context, ref int operations)
    {
        if (--operations < 0) throw new RuleEvaluationException("Rule operation budget exceeded.");
        return expression switch
        {
            ConstantExpression constant => ValidateConstant(constant.Value),
            FieldExpression field => ResolveField(field, context),
            CompareExpression comparison => Compare(
                comparison.Operator,
                EvaluateValue(comparison.Left, context, ref operations),
                EvaluateValue(comparison.Right, context, ref operations)),
            LogicalExpression logical => EvaluateLogical(logical, context, ref operations),
            NotExpression not => !RequireBoolean(EvaluateValue(not.Operand, context, ref operations)),
            _ => throw new RuleEvaluationException("Unsupported rule expression."),
        };
    }

    private object? ResolveField(FieldExpression field, RuleEvaluationContext context)
    {
        string[] segments = field.Path.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 0 || segments.Length > maximumPathDepth
            || segments.Any(static segment => !IsIdentifier(segment)))
            throw new RuleEvaluationException("Invalid field path.");
        object? current = field.Source == RuleDataSource.Request ? context.Request : context.AuthoritativeState;
        foreach (string segment in segments)
        {
            if (current is not IReadOnlyDictionary<string, object?> dictionary
                || !dictionary.TryGetValue(segment, out current))
                throw new RuleEvaluationException("Required field is missing.");
        }
        return ValidateConstant(current);
    }

    private object EvaluateLogical(LogicalExpression expression, RuleEvaluationContext context, ref int operations)
    {
        if (expression.Operands.Count is < 1 or > 64)
            throw new RuleEvaluationException("Logical operand count is invalid.");
        if (expression.Operator == LogicalOperator.All)
        {
            foreach (RuleExpression operand in expression.Operands)
                if (!RequireBoolean(EvaluateValue(operand, context, ref operations))) return false;
            return true;
        }
        foreach (RuleExpression operand in expression.Operands)
            if (RequireBoolean(EvaluateValue(operand, context, ref operations))) return true;
        return false;
    }

    private static bool Compare(ComparisonOperator operation, object? left, object? right)
    {
        if (left is null || right is null)
            return operation switch { ComparisonOperator.Equal => left is null && right is null,
                ComparisonOperator.NotEqual => left is not null || right is not null,
                _ => throw new RuleEvaluationException("Null values are not ordered.") };

        if (TryDecimal(left, out decimal leftNumber) && TryDecimal(right, out decimal rightNumber))
            return ApplyComparison(operation, leftNumber.CompareTo(rightNumber));
        if (left is string leftString && right is string rightString)
            return ApplyComparison(operation, string.CompareOrdinal(leftString, rightString));
        if (left is bool leftBool && right is bool rightBool)
            return ApplyComparison(operation, leftBool.CompareTo(rightBool));
        throw new RuleEvaluationException("Compared values have incompatible types.");
    }

    private static bool ApplyComparison(ComparisonOperator operation, int comparison) => operation switch
    {
        ComparisonOperator.Equal => comparison == 0,
        ComparisonOperator.NotEqual => comparison != 0,
        ComparisonOperator.Less => comparison < 0,
        ComparisonOperator.LessOrEqual => comparison <= 0,
        ComparisonOperator.Greater => comparison > 0,
        ComparisonOperator.GreaterOrEqual => comparison >= 0,
        _ => throw new RuleEvaluationException("Unknown comparison operator."),
    };

    private static bool TryDecimal(object value, out decimal number)
    {
        if (value is float or double) throw new RuleEvaluationException("Floating-point values are prohibited in deterministic rules.");
        return decimal.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture),
            NumberStyles.Number, CultureInfo.InvariantCulture, out number);
    }

    private static object? ValidateConstant(object? value)
    {
        if (value is null or string or bool or byte or sbyte or short or ushort or int or uint or long or ulong or decimal)
            return value;
        throw new RuleEvaluationException("Unsupported value type.");
    }

    private static bool RequireBoolean(object? value) => value is bool boolean
        ? boolean : throw new RuleEvaluationException("Logical operands must be boolean.");

    private static bool IsIdentifier(string value) => value.Length is >= 1 and <= 64
        && (char.IsAsciiLetter(value[0]) || value[0] == '_')
        && value.All(static character => char.IsAsciiLetterOrDigit(character) || character == '_');
}

public sealed class RuleEvaluationException(string message) : Exception(message);

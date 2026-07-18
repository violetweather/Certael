using System.Text.Json;

namespace Certael.Server.Evidence;

public enum EvidenceSortField { CreatedAt, Risk, Confidence, Player, Rule, Signal }
public enum EvidenceSortDirection { Ascending, Descending }

public sealed record EvidenceSummary(
    Guid VerdictId, string TenantId, string GameId, string EnvironmentId,
    string SessionId, string PlayerSubject, int RiskScore, double Confidence,
    VerdictRecommendation Recommendation, IReadOnlyList<string> RuleIds,
    IReadOnlyList<SignalFamily> SignalFamilies, int FindingCount,
    DateTimeOffset CreatedAt);

public sealed record EvidenceSearchQuery(
    string TenantId, string EnvironmentId, string? Search = null,
    string? PlayerSubject = null, string? SessionId = null, string? RuleId = null,
    SignalFamily? SignalFamily = null,
    VerdictRecommendation? Recommendation = null,
    EvidenceSortField SortBy = EvidenceSortField.CreatedAt,
    EvidenceSortDirection SortDirection = EvidenceSortDirection.Descending,
    string? Cursor = null, int PageSize = 50);

public sealed record EvidenceSearchPage(
    IReadOnlyList<EvidenceSummary> Items, string? NextCursor, bool HasMore);

public sealed record EvidenceSearchCursor(string SortValue, Guid VerdictId);

public static class EvidenceSearchCursorCodec
{
    public static string Encode(EvidenceSearchCursor cursor) => Convert.ToBase64String(
        JsonSerializer.SerializeToUtf8Bytes(cursor), Base64FormattingOptions.None)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static EvidenceSearchCursor Decode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512)
            throw new ArgumentException("Evidence search cursor is invalid.");
        try
        {
            string padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            EvidenceSearchCursor? cursor = JsonSerializer.Deserialize<EvidenceSearchCursor>(
                Convert.FromBase64String(padded));
            if (cursor is null || cursor.VerdictId == Guid.Empty || cursor.SortValue.Length > 256)
                throw new ArgumentException("Evidence search cursor is invalid.");
            return cursor;
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw new ArgumentException("Evidence search cursor is invalid.", exception);
        }
    }
}

using System.Text.Json;

namespace Certael.Server.Cases;

public sealed record CaseQueueCursor(string SortValue, Guid CaseId);

public static class CaseQueueCursorCodec
{
    public static string Encode(CaseQueueCursor cursor) => Convert.ToBase64String(
        JsonSerializer.SerializeToUtf8Bytes(cursor), Base64FormattingOptions.None)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static CaseQueueCursor Decode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512)
            throw new ArgumentException("Case queue cursor is invalid.");
        try
        {
            string padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            CaseQueueCursor? cursor = JsonSerializer.Deserialize<CaseQueueCursor>(
                Convert.FromBase64String(padded));
            if (cursor is null || cursor.CaseId == Guid.Empty || cursor.SortValue.Length > 256)
                throw new ArgumentException("Case queue cursor is invalid.");
            return cursor;
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw new ArgumentException("Case queue cursor is invalid.", exception);
        }
    }
}

namespace Certael.Server.Privacy;

public sealed record PlayerCaseRedactionResult(int CasesPseudonymized, int CoreSessionsDeleted);

public interface IPlayerDataPrivacyStore
{
    IAsyncEnumerable<string> ExportNdjsonAsync(string tenantId, string environmentId,
        string playerSubject, CancellationToken cancellationToken);

    ValueTask<PlayerCaseRedactionResult> PseudonymizeCasesAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken);
}

public sealed class EmptyPlayerDataPrivacyStore : IPlayerDataPrivacyStore
{
    public async IAsyncEnumerable<string> ExportNdjsonAsync(string tenantId,
        string environmentId, string playerSubject,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask;
        yield break;
    }

    public ValueTask<PlayerCaseRedactionResult> PseudonymizeCasesAsync(string tenantId,
        string environmentId, string playerSubject, CancellationToken cancellationToken) =>
        ValueTask.FromResult(new PlayerCaseRedactionResult(0, 0));
}

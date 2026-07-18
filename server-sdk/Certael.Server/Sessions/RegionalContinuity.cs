using System.Net;
using System.Net.Http.Json;

namespace Certael.Server.Sessions;

public sealed record RegionalLeaseV1(string TenantId, string GameId, string EnvironmentId,
    string MatchId, string OwnerRegion, string OwnerServer, long FencingEpoch,
    DateTimeOffset ExpiresAt);
public sealed record RegionalFenceRequest(string TenantId, string GameId, string EnvironmentId,
    string MatchId, string Region, string ServerId, long FencingEpoch);

public interface IRegionalActionFence
{
    ValueTask<bool> IsCurrentOwnerAsync(RegionalFenceRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class CoordinatorRegionalActionFence(HttpClient client) : IRegionalActionFence
{
    public async ValueTask<bool> IsCurrentOwnerAsync(RegionalFenceRequest request,
        CancellationToken cancellationToken = default)
    {
        Validate(request);
        if (client.BaseAddress is null || !client.BaseAddress.IsAbsoluteUri
            || client.BaseAddress.Scheme != Uri.UriSchemeHttps
                && !(client.BaseAddress.IsLoopback
                    && client.BaseAddress.Scheme == Uri.UriSchemeHttp))
            throw new RegionalContinuityException(
                "Coordinator must use HTTPS except on loopback.");
        var lease = new RegionalLeaseV1(request.TenantId, request.GameId,
            request.EnvironmentId, request.MatchId, request.Region, request.ServerId,
            request.FencingEpoch, DateTimeOffset.UnixEpoch);
        using HttpResponseMessage response = await client.PostAsJsonAsync(
            "v1/leases/validate", lease, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NoContent) return true;
        if (response.StatusCode == HttpStatusCode.Conflict) return false;
        throw new RegionalContinuityException("Coordinator lease validation is unavailable.");
    }

    private static void Validate(RegionalFenceRequest value)
    {
        string[] identifiers = [value.TenantId, value.GameId, value.EnvironmentId,
            value.MatchId, value.Region, value.ServerId];
        if (value.FencingEpoch < 1 || identifiers.Any(identifier =>
                string.IsNullOrWhiteSpace(identifier) || identifier.Length > 128
                || identifier.Any(character => !char.IsAsciiLetterOrDigit(character)
                    && character is not ('.' or '_' or '-' or ':'))))
            throw new RegionalContinuityException("Regional fence request is invalid.");
    }
}

public sealed record AcquireRegionalLeaseRequest(string TenantId, string GameId,
    string EnvironmentId, string MatchId, string Region, string ServerId,
    bool Force = false);
public sealed record IssueRegionTransferRequest(RegionalLeaseV1 Lease,
    string PlayerSubject, string DestinationRegion);
public sealed record RedeemRegionTransferRequest(SignedRegionTransferGrant Grant);
public sealed record RegionTransferRedemption(RegionalLeaseV1 Lease,
    bool FreshCoreSessionRequired, bool FreshAgentSessionRequired);

/// <summary>Bounded mTLS client for the Certael regional coordinator.</summary>
public sealed class CoordinatorLeaseClient
{
    private readonly HttpClient _client;

    public CoordinatorLeaseClient(HttpClient client)
    {
        EnsureSecure(client);
        _client = client;
    }

    public async ValueTask<RegionalLeaseV1?> AcquireAsync(
        AcquireRegionalLeaseRequest request, CancellationToken cancellationToken = default)
    {
        ValidateIdentifiers(request.TenantId, request.GameId, request.EnvironmentId,
            request.MatchId, request.Region, request.ServerId);
        using HttpResponseMessage response = await SendAsync("v1/leases/acquire", request,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict) return null;
        return await ReadRequiredAsync<RegionalLeaseV1>(response, cancellationToken);
    }

    public async ValueTask<RegionalLeaseV1?> RenewAsync(RegionalLeaseV1 lease,
        CancellationToken cancellationToken = default)
    {
        ValidateLease(lease);
        using HttpResponseMessage response = await SendAsync("v1/leases/renew", lease,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict) return null;
        return await ReadRequiredAsync<RegionalLeaseV1>(response, cancellationToken);
    }

    public async ValueTask<bool> ReleaseAsync(RegionalLeaseV1 lease,
        CancellationToken cancellationToken = default)
    {
        ValidateLease(lease);
        using HttpResponseMessage response = await SendAsync("v1/leases/release",
            new { Lease = lease }, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NoContent) return true;
        if (response.StatusCode == HttpStatusCode.Conflict) return false;
        throw Unavailable(response);
    }

    public async ValueTask<SignedRegionTransferGrant?> IssueTransferAsync(
        IssueRegionTransferRequest request, CancellationToken cancellationToken = default)
    {
        ValidateLease(request.Lease);
        ValidateIdentifiers(request.PlayerSubject, request.DestinationRegion);
        using HttpResponseMessage response = await SendAsync("v1/transfers", request,
            cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict) return null;
        return await ReadRequiredAsync<SignedRegionTransferGrant>(response, cancellationToken);
    }

    public async ValueTask<RegionTransferRedemption?> RedeemTransferAsync(
        SignedRegionTransferGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        using HttpResponseMessage response = await SendAsync("v1/transfers/redeem",
            new RedeemRegionTransferRequest(grant), cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict) return null;
        return await ReadRequiredAsync<RegionTransferRedemption>(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendAsync<T>(string path, T body,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _client.PostAsJsonAsync(path, body, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException
            or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new RegionalContinuityException(
                "Coordinator request is unavailable.", exception);
        }
    }

    private static async ValueTask<T> ReadRequiredAsync<T>(HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode) throw Unavailable(response);
        try
        {
            return await response.Content.ReadFromJsonAsync<T>(cancellationToken)
                ?? throw new RegionalContinuityException(
                    "Coordinator returned an empty response.");
        }
        catch (Exception exception) when (exception is System.Text.Json.JsonException
            or NotSupportedException)
        {
            throw new RegionalContinuityException(
                "Coordinator returned an invalid response.", exception);
        }
    }

    private static RegionalContinuityException Unavailable(HttpResponseMessage response) =>
        new($"Coordinator rejected the request with status {(int)response.StatusCode}.");

    private static void EnsureSecure(HttpClient client)
    {
        if (client.BaseAddress is null || !client.BaseAddress.IsAbsoluteUri
            || client.BaseAddress.Scheme != Uri.UriSchemeHttps
                && !(client.BaseAddress.IsLoopback
                    && client.BaseAddress.Scheme == Uri.UriSchemeHttp))
            throw new RegionalContinuityException(
                "Coordinator must use HTTPS except on loopback.");
    }

    private static void ValidateLease(RegionalLeaseV1 lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateIdentifiers(lease.TenantId, lease.GameId, lease.EnvironmentId,
            lease.MatchId, lease.OwnerRegion, lease.OwnerServer);
        if (lease.FencingEpoch < 1)
            throw new RegionalContinuityException("Regional lease is invalid.");
    }

    private static void ValidateIdentifiers(params string[] identifiers)
    {
        if (identifiers.Any(identifier => string.IsNullOrWhiteSpace(identifier)
            || identifier.Length > 128 || identifier.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not ('.' or '_' or '-' or ':'))))
            throw new RegionalContinuityException("Regional identifier is invalid.");
    }
}

public sealed record RegionalLeaseLoss(RegionalLeaseV1 Lease, string PublicReason);

/// <summary>
/// Renews a 30-second ownership lease every 10 seconds and closes the local
/// protected-action gate when ownership becomes stale or cannot be renewed.
/// </summary>
public sealed class RegionalLeaseSupervisor : IAsyncDisposable
{
    public static readonly TimeSpan RenewalInterval = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan OutageRetryInterval = TimeSpan.FromSeconds(2);

    private readonly CoordinatorLeaseClient _client;
    private readonly TimeProvider _clock;
    private readonly Func<RegionalLeaseV1, ValueTask> _onRenewed;
    private readonly Func<RegionalLeaseLoss, ValueTask> _onLost;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _sync = new();
    private RegionalLeaseV1 _lease;
    private Task? _loop;
    private int _accepting = 1;
    private int _lossReported;

    public RegionalLeaseSupervisor(CoordinatorLeaseClient client, RegionalLeaseV1 lease,
        TimeProvider? clock = null,
        Func<RegionalLeaseV1, ValueTask>? onRenewed = null,
        Func<RegionalLeaseLoss, ValueTask>? onLost = null)
    {
        _client = client;
        _lease = lease;
        _clock = clock ?? TimeProvider.System;
        _onRenewed = onRenewed ?? (_ => ValueTask.CompletedTask);
        _onLost = onLost ?? (_ => ValueTask.CompletedTask);
        if (lease.FencingEpoch < 1 || lease.ExpiresAt <= _clock.GetUtcNow())
            throw new RegionalContinuityException("Regional lease is already expired.");
    }

    public RegionalLeaseV1 CurrentLease
    {
        get { lock (_sync) return _lease; }
    }

    public bool IsAcceptingProtectedActions => Volatile.Read(ref _accepting) == 1
        && CurrentLease.ExpiresAt > _clock.GetUtcNow();

    public void Start()
    {
        if (Interlocked.CompareExchange(ref _loop,
                Task.Run(() => RunAsync(_stop.Token)), null) is not null)
            throw new InvalidOperationException("Regional lease supervisor is already running.");
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        TimeSpan nextDelay = RenewalInterval;
        while (!cancellationToken.IsCancellationRequested)
        {
            try { await Task.Delay(nextDelay, _clock, cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            { return; }

            RegionalLeaseV1 current = CurrentLease;
            if (current.ExpiresAt <= _clock.GetUtcNow())
            {
                await LoseAsync(current, "REGIONAL_LEASE_EXPIRED");
                return;
            }
            try
            {
                RegionalLeaseV1? renewed = await _client.RenewAsync(current,
                    cancellationToken);
                if (renewed is null)
                {
                    await LoseAsync(current, "STALE_FENCING_EPOCH");
                    return;
                }
                if (renewed.FencingEpoch != current.FencingEpoch
                    || renewed.OwnerServer != current.OwnerServer
                    || renewed.MatchId != current.MatchId
                    || renewed.ExpiresAt <= _clock.GetUtcNow())
                {
                    await LoseAsync(current, "INVALID_LEASE_RENEWAL");
                    return;
                }
                lock (_sync) _lease = renewed;
                await _onRenewed(renewed);
                nextDelay = RenewalInterval;
            }
            catch (RegionalContinuityException)
            {
                current = CurrentLease;
                if (current.ExpiresAt <= _clock.GetUtcNow() + OutageRetryInterval)
                {
                    await LoseAsync(current, "COORDINATOR_UNAVAILABLE");
                    return;
                }
                nextDelay = OutageRetryInterval;
            }
        }
    }

    private async ValueTask LoseAsync(RegionalLeaseV1 lease, string reason)
    {
        Volatile.Write(ref _accepting, 0);
        if (Interlocked.Exchange(ref _lossReported, 1) == 0)
            await _onLost(new RegionalLeaseLoss(lease, reason));
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        if (_loop is not null)
        {
            try { await _loop; }
            catch (OperationCanceledException) { }
        }
        RegionalLeaseV1 lease = CurrentLease;
        Volatile.Write(ref _accepting, 0);
        if (lease.ExpiresAt > _clock.GetUtcNow())
        {
            try { await _client.ReleaseAsync(lease); }
            catch (RegionalContinuityException) { }
        }
        _stop.Dispose();
    }
}

public sealed class RegionalContinuityException(string message, Exception? inner = null)
    : Exception(message, inner);

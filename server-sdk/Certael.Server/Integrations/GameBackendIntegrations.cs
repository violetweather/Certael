using System.Security.Cryptography;

namespace Certael.Server.Integrations;

public sealed record ExternalIdentityAssertion(string Provider, string ApplicationId,
    byte[] OpaqueAssertion, DateTimeOffset ExpiresAt);
public sealed record VerifiedPlayerIdentity(string Provider, string Subject, string ApplicationId,
    DateTimeOffset VerifiedAt, byte[] ClaimsDigest);
public sealed record AuthoritativeServerIdentity(string Provider, string ServerId, string ApplicationId,
    string Region, DateTimeOffset VerifiedAt);
public sealed record SessionBindingRequest(string TenantId, string GameId, string EnvironmentId,
    VerifiedPlayerIdentity Player, AuthoritativeServerIdentity Server, string MatchId, byte[] ProofKey);
public sealed record BoundExternalSession(string SessionId, string PlayerSubject, string ServerId,
    string MatchId, DateTimeOffset ExpiresAt);
public sealed record GameBackendSessionRequest(ExternalIdentityAssertion PlayerAssertion,
    string ServerApplicationId, string ServerCredential, string TenantId, string GameId,
    string EnvironmentId, string MatchId, byte[] ProofKey);
public sealed record GameBackendSession(string TenantId, BoundExternalSession Session,
    VerifiedPlayerIdentity Player, AuthoritativeServerIdentity Server);

public interface IPlayerIdentityVerifier
{
    string Provider { get; }
    ValueTask<VerifiedPlayerIdentity> VerifyAsync(ExternalIdentityAssertion assertion,
        CancellationToken cancellationToken = default);
}

public interface IServerIdentityVerifier
{
    string Provider { get; }
    ValueTask<AuthoritativeServerIdentity> VerifyAsync(string applicationId, string serverCredential,
        CancellationToken cancellationToken = default);
}

public interface IExternalSessionBinder
{
    ValueTask<BoundExternalSession> BindAsync(SessionBindingRequest request,
        CancellationToken cancellationToken = default);
    ValueTask RevokeAsync(string tenantId, string sessionId, string reason,
        CancellationToken cancellationToken = default);
}

public interface IAgentLifecycleIntegration
{
    ValueTask StartAsync(BoundExternalSession session, CancellationToken cancellationToken = default);
    ValueTask StopAsync(BoundExternalSession session, string reason, CancellationToken cancellationToken = default);
}

public interface IGameBackendSessionIntegration
{
    ValueTask<GameBackendSession> StartAsync(GameBackendSessionRequest request,
        CancellationToken cancellationToken = default);
    ValueTask StopAsync(GameBackendSession session, string reason,
        CancellationToken cancellationToken = default);
}

/// <summary>Composes provider verification with Core binding and Agent lifecycle.</summary>
public sealed class GameBackendSessionIntegration(
    IPlayerIdentityVerifier players,
    IServerIdentityVerifier servers,
    IExternalSessionBinder sessions,
    IAgentLifecycleIntegration agent,
    TimeProvider clock) : IGameBackendSessionIntegration
{
    public async ValueTask<GameBackendSession> StartAsync(GameBackendSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        long started = IntegrationTelemetry.Start();
        string outcome = "failed";
        try
        {
            GameBackendSession result = await StartCoreAsync(request, cancellationToken);
            outcome = "succeeded";
            return result;
        }
        catch (IntegrationException exception) { outcome = exception.PublicReason; throw; }
        catch (OperationCanceledException) { outcome = "canceled"; throw; }
        finally
        {
            IntegrationTelemetry.Record("start", players.Provider, servers.Provider,
                outcome, started);
        }
    }

    private async ValueTask<GameBackendSession> StartCoreAsync(GameBackendSessionRequest request,
        CancellationToken cancellationToken)
    {
        IntegrationValidation.ValidateSessionRequest(request, clock.GetUtcNow());
        if (players.Provider != request.PlayerAssertion.Provider)
            throw new IntegrationException("PLAYER_PROVIDER_MISMATCH",
                "Configured player provider does not match the assertion.");
        VerifiedPlayerIdentity player;
        try { player = await players.VerifyAsync(request.PlayerAssertion, cancellationToken); }
        catch (Exception exception) when (exception is not (IntegrationException
            or OperationCanceledException))
        { throw new IntegrationException("PLAYER_PROVIDER_UNAVAILABLE",
            "Player identity provider is unavailable."); }
        AuthoritativeServerIdentity server;
        try { server = await servers.VerifyAsync(request.ServerApplicationId,
            request.ServerCredential, cancellationToken); }
        catch (Exception exception) when (exception is not (IntegrationException
            or OperationCanceledException))
        { throw new IntegrationException("SERVER_PROVIDER_UNAVAILABLE",
            "Server identity provider is unavailable."); }
        IntegrationValidation.ValidateVerifiedContext(request, player, server, clock.GetUtcNow());
        BoundExternalSession bound;
        try
        {
            bound = await sessions.BindAsync(new SessionBindingRequest(
                request.TenantId, request.GameId, request.EnvironmentId, player, server,
                request.MatchId, Uint8Array(request.ProofKey)), cancellationToken);
        }
        catch (Exception exception) when (exception is not (IntegrationException
            or OperationCanceledException))
        { throw new IntegrationException("CORE_BINDING_UNAVAILABLE",
            "Core session binding is unavailable."); }
        try
        {
            IntegrationValidation.ValidateBoundSession(request, player, server, bound,
                clock.GetUtcNow());
            await agent.StartAsync(bound, cancellationToken);
            return new GameBackendSession(request.TenantId, bound, player, server);
        }
        catch (Exception exception)
        {
            await RollBackLaunchAsync(bound, CancellationToken.None);
            if (exception is OperationCanceledException) throw;
            if (exception is IntegrationException) throw;
            throw new IntegrationException("AGENT_LAUNCH_FAILED",
                "Agent lifecycle failed after Core session binding.");
        }
    }

    public async ValueTask StopAsync(GameBackendSession session, string reason,
        CancellationToken cancellationToken = default)
    {
        long started = IntegrationTelemetry.Start();
        string outcome = "failed";
        try
        {
            await StopCoreAsync(session, reason, cancellationToken);
            outcome = "succeeded";
        }
        catch (IntegrationException exception) { outcome = exception.PublicReason; throw; }
        catch (OperationCanceledException) { outcome = "canceled"; throw; }
        finally
        {
            IntegrationTelemetry.Record("stop", session.Player.Provider,
                session.Server.Provider, outcome, started);
        }
    }

    private async ValueTask StopCoreAsync(GameBackendSession session, string reason,
        CancellationToken cancellationToken)
    {
        if (!IntegrationValidation.Identifier(reason, 256))
            throw new IntegrationException("INVALID_REVOCATION_REASON",
                "Integration revocation reason is invalid.");
        Exception? agentFailure = null;
        try { await agent.StopAsync(session.Session, reason, cancellationToken); }
        catch (Exception exception)
        { agentFailure = exception; }
        await sessions.RevokeAsync(session.TenantId, session.Session.SessionId, reason,
            cancellationToken.IsCancellationRequested ? CancellationToken.None : cancellationToken);
        if (agentFailure is not null)
        {
            if (agentFailure is OperationCanceledException)
                throw new OperationCanceledException("Agent shutdown was canceled after Core revocation.",
                    agentFailure, cancellationToken);
            throw new IntegrationException("AGENT_STOP_FAILED",
                "Core session was revoked but Agent shutdown failed.");
        }
    }

    private async ValueTask RollBackLaunchAsync(BoundExternalSession bound,
        CancellationToken cancellationToken)
    {
        try { await agent.StopAsync(bound, "agent-launch-failed", cancellationToken); }
        catch (Exception) { }
        await sessions.RevokeAsync("integration-rollback", bound.SessionId,
            "agent-launch-failed", cancellationToken);
    }

    private static byte[] Uint8Array(byte[] value) => value.ToArray();
}

public sealed class IntegrationException(string publicReason, string message,
    Exception? innerException = null) : Exception(message, innerException)
{
    public string PublicReason { get; } = publicReason;
}

public static class IntegrationValidation
{
    public static VerifiedPlayerIdentity Verified(string provider, string subject, string applicationId,
        ReadOnlySpan<byte> authoritativeClaims, DateTimeOffset now)
    {
        if (!Identifier(provider) || !Identifier(subject) || !Identifier(applicationId)
            || authoritativeClaims.IsEmpty || authoritativeClaims.Length > 1024 * 1024)
            throw new IntegrationException("INVALID_PROVIDER_RESPONSE", "Provider identity response is incomplete.");
        return new VerifiedPlayerIdentity(provider, subject, applicationId, now,
            SHA256.HashData(authoritativeClaims));
    }

    public static void ValidateAssertion(ExternalIdentityAssertion assertion,
        string expectedProvider, DateTimeOffset now)
    {
        if (assertion is null || assertion.Provider != expectedProvider
            || !Identifier(assertion.Provider) || !Identifier(assertion.ApplicationId)
            || assertion.OpaqueAssertion is null or { Length: < 1 or > 1024 * 1024 }
            || assertion.ExpiresAt <= now || assertion.ExpiresAt > now.AddMinutes(15))
            throw new IntegrationException("INVALID_IDENTITY_ASSERTION",
                "External identity assertion is malformed, expired, or misclassified.");
    }

    public static void ValidateServerRequest(string applicationId, string credential)
    {
        if (!Identifier(applicationId) || string.IsNullOrWhiteSpace(credential)
            || credential.Length > 16 * 1024 || credential.Any(char.IsControl))
            throw new IntegrationException("INVALID_SERVER_ASSERTION",
                "Authoritative server assertion is malformed.");
    }

    public static void ValidateSessionRequest(GameBackendSessionRequest request,
        DateTimeOffset now)
    {
        if (request is null || request.PlayerAssertion is null
            || !Identifier(request.TenantId) || !Identifier(request.GameId)
            || !Identifier(request.EnvironmentId) || !Identifier(request.MatchId)
            || !Identifier(request.ServerApplicationId)
            || request.ProofKey is null or { Length: not 32 })
            throw new IntegrationException("INVALID_SESSION_BINDING",
                "Game-backend session request is malformed.");
        ValidateAssertion(request.PlayerAssertion, request.PlayerAssertion.Provider, now);
        ValidateServerRequest(request.ServerApplicationId, request.ServerCredential);
    }

    public static void ValidateVerifiedContext(GameBackendSessionRequest request,
        VerifiedPlayerIdentity player, AuthoritativeServerIdentity server,
        DateTimeOffset now)
    {
        if (player is null || server is null || !Identifier(player.Provider)
            || !Identifier(player.Subject)
            || player.ApplicationId != request.PlayerAssertion.ApplicationId
            || player.ClaimsDigest is null or { Length: not 32 }
            || player.VerifiedAt > now || now - player.VerifiedAt > TimeSpan.FromMinutes(5)
            || !Identifier(server.Provider) || !Identifier(server.ServerId)
            || server.ApplicationId != request.ServerApplicationId
            || !Identifier(server.Region) || server.VerifiedAt > now
            || now - server.VerifiedAt > TimeSpan.FromMinutes(5))
            throw new IntegrationException("INVALID_VERIFIED_CONTEXT",
                "Provider verification context is incomplete or stale.");
    }

    public static void ValidateBoundSession(GameBackendSessionRequest request,
        VerifiedPlayerIdentity player, AuthoritativeServerIdentity server,
        BoundExternalSession bound, DateTimeOffset now)
    {
        if (bound is null || !Identifier(bound.SessionId) || bound.PlayerSubject != player.Subject
            || bound.ServerId != server.ServerId || bound.MatchId != request.MatchId
            || bound.ExpiresAt <= now || bound.ExpiresAt > now.AddHours(24))
            throw new IntegrationException("SESSION_BINDING_MISMATCH",
                "Core returned a session outside the verified provider binding.");
    }

    public static bool Identifier(string value, int maximum = 128) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-' or ':');
}

using System.Collections.Immutable;
using Certael.Persistence.Postgres;
using Certael.Persistence.Redis;
using Certael.Server.Actions;
using Certael.Server.Evidence;
using Certael.Server.Sessions;
using Certael.Server.Agent;
using Certael.Server.Configuration;
using Certael.Server.Protections;
using Certael.Server.Rules;
using Npgsql;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace Certael.Server.Tests;

[Collection("Persistence")]
public sealed class PersistenceIntegrationTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task PostgresPersistsSessionsOutboxResultsAndTenantIsolatedEvidence()
    {
        string? connectionString = Environment.GetEnvironmentVariable("CERTAEL_TEST_POSTGRES");
        if (connectionString is null) { Assert.Skip("CERTAEL_TEST_POSTGRES is not configured."); return; }
        CancellationToken token = TestContext.Current.CancellationToken;
        await using NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);
        await new PostgresMigrationRunner(dataSource).ApplyAsync(token);
        await ResetPostgres(dataSource, token);

        var durableTickets = new PostgresTicketRedemptionStore(dataSource);
        Assert.False(await durableTickets.TryRedeemAsync("tenant/escape", "test",
            Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(1), token));
        Guid durableTicket = Guid.NewGuid();
        DateTimeOffset durableTicketExpiry = DateTimeOffset.UtcNow.AddMinutes(1);
        bool[] ticketRedemptions = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            durableTickets.TryRedeemAsync("tenant-a", "test", durableTicket,
                durableTicketExpiry, token).AsTask()));
        Assert.Equal(1, ticketRedemptions.Count(value => value));
        Assert.True(await durableTickets.TryRedeemAsync("tenant-b", "test", durableTicket,
            durableTicketExpiry, token));

        var session = new SessionAuthorization("session-a", "tenant-a", "game", "test", "player", "match",
            "server", "build", DateTimeOffset.UtcNow.AddMinutes(30), 1, 1000, new byte[32]);
        var sessions = new PostgresSessionStore(dataSource);
        await sessions.CreateAsync(session, token);
        await sessions.CreateAsync(session with { SessionId = "session-b", TenantId = "tenant-b" }, token);
        SessionAuthorization? persistedSession = await sessions.FindAsync("tenant-a", session.SessionId, token);
        Assert.NotNull(persistedSession);
        Assert.Equal(session.SessionId, persistedSession.SessionId);
        Assert.Equal(session.TenantId, persistedSession.TenantId);
        Assert.Equal(session.EphemeralPublicKey.ToArray(), persistedSession.EphemeralPublicKey.ToArray());
        DateTimeOffset renewedExpiry = DateTimeOffset.UtcNow.AddHours(1);
        Assert.False(await sessions.RenewAsync("tenant-a", "session-a", "wrong-server", renewedExpiry, token));
        Assert.True(await sessions.RenewAsync("tenant-a", "session-a", "server", renewedExpiry, token));
        Assert.Equal(renewedExpiry.ToUnixTimeSeconds(),
            (await sessions.FindAsync("tenant-a", "session-a", token))!.ExpiresAt.ToUnixTimeSeconds());

        var agentStore = new PostgresAgentSessionStore(dataSource);
        var agentSession = new VerifiedAgentSession("agent-a", "tenant-a", "game", "test",
            "player", "match", "build", new byte[32], 0, new byte[32],
            DateTimeOffset.UtcNow.AddMinutes(5), "server-a");
        await agentStore.CreateAsync(agentSession, token);
        Assert.NotNull(await agentStore.FindAsync("tenant-a", "agent-a", token));
        Assert.Null(await agentStore.FindAsync("tenant-b", "agent-a", token));
        byte[] agentChallenge = RandomNumberGenerator.GetBytes(32);
        Assert.True(await agentStore.SetChallengeAsync("tenant-a", "agent-a", agentChallenge,
            DateTimeOffset.UtcNow.AddSeconds(30), token));
        AgentSessionAdmission? admission = await agentStore.FindAdmissionAsync(
            "tenant-a", "agent-a", token);
        Assert.NotNull(admission);
        Assert.Equal("server-a", admission.Session.AuthoritativeServerId);
        Assert.Equal(agentChallenge, admission.Challenge);
        AgentStoredHealth? initialHealth = await agentStore.HealthAsync("tenant-a", "agent-a", token);
        Assert.NotNull(initialHealth);
        Assert.Equal("server-a", initialHealth.AuthoritativeServerId);
        Assert.Null(initialHealth.LastReportAt);
        var agentReport = new AgentIntegrityReport(1, "agent-a", 1, agentChallenge,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "build", new byte[32], [],
            new byte[32], new byte[64]);
        byte[] canonicalAgentReport = AgentReportCodec.Encode(agentReport);
        byte[] agentDigest = AgentReportCodec.Digest(agentReport);
        DateTimeOffset agentAcceptedAt = DateTimeOffset.UtcNow;
        bool[] agentCommits = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            agentStore.CommitReportAsync("tenant-a", agentReport, canonicalAgentReport,
                agentDigest, agentAcceptedAt, token).AsTask()));
        Assert.Equal(1, agentCommits.Count(value => value));
        AgentStoredHealth? reportedHealth = await agentStore.HealthAsync("tenant-a", "agent-a", token);
        Assert.NotNull(reportedHealth?.LastReportAt);
        await using (NpgsqlCommand retention = dataSource.CreateCommand(
            "SELECT expires_at FROM certael_agent_reports WHERE tenant_id='tenant-a' " +
            "AND agent_session_id='agent-a' AND sequence=1"))
        {
            object value = (await retention.ExecuteScalarAsync(token))!;
            DateTimeOffset expiresAt = value is DateTime timestamp
                ? new DateTimeOffset(DateTime.SpecifyKind(timestamp, DateTimeKind.Utc))
                : (DateTimeOffset)value;
            Assert.InRange(expiresAt, agentAcceptedAt.AddHours(24).AddSeconds(-1),
                agentAcceptedAt.AddHours(24).AddSeconds(1));
        }

        using Key policyKey = Key.Create(SignatureAlgorithm.Ed25519);
        var policyStore = new PostgresAgentPolicyStore(dataSource,
            new AgentGrantSigner(policyKey, "agent-policy-key"), TimeProvider.System);
        DateTimeOffset policyExpiry = DateTimeOffset.UtcNow.AddHours(1);
        var policyClaims = new AgentPolicyClaims(1, "competitive-default", "tenant-a",
            "game", "test", AgentRequirementMode.Required, 15, 60, 30, "0.1.0",
            policyExpiry);
        await policyStore.AddDraftAsync(policyClaims, "author", token);
        await policyStore.ApproveAsync("tenant-a", policyClaims.PolicyId, "reviewer-a", token);
        await policyStore.ApproveAsync("tenant-a", policyClaims.PolicyId, "reviewer-b", token);
        AgentPolicyDeployment active = await policyStore.PromoteAsync("tenant-a",
            policyClaims.PolicyId, AgentPolicyDeploymentStage.Enforced, 0, "operator", token);
        Assert.Equal(2, active.Approvals.Count);
        AgentPolicyClaims resolvedPolicy = (await policyStore.ResolveAsync(policyClaims.PolicyId,
            "tenant-a", "game", "test", "player\0match", DateTimeOffset.UtcNow, token)).Claims;
        Assert.Equal(policyClaims with { ExpiresAt = resolvedPolicy.ExpiresAt }, resolvedPolicy);
        Assert.InRange((policyClaims.ExpiresAt - resolvedPolicy.ExpiresAt).Duration(),
            TimeSpan.Zero, TimeSpan.FromMilliseconds(1));
        await Assert.ThrowsAsync<AgentPolicyLifecycleException>(async () =>
            await policyStore.GetAsync("tenant-b", policyClaims.PolicyId, token));

        using ECDsa configurationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var configurationVerifier = new SignedConfigurationVerifier(
            new RulePackVerifier(new Dictionary<string, ECDsa> { ["configuration-key"] = configurationKey }),
            new ProtectionProfileVerifier(new Dictionary<string, ECDsa> { ["configuration-key"] = configurationKey }));
        var configurationStore = new PostgresSignedConfigurationStore(dataSource,
            configurationVerifier, TimeProvider.System);
        var profileCompiler = new ProtectionProfileCompiler(configurationKey, "configuration-key");
        ProtectionProfile Profile(string version) => new("tenant-a", "competitive", version,
            "game", "test", new Dictionary<string, ProtectionActionPolicy>
            {
                ["inventory.craft"] = new("example.Craft.v1", 1, new(10, 10_000),
                    ["economy", "revision"])
            }, new(AdmissionUnavailableMode.Deny, RulesUnavailableMode.Indeterminate));
        SignedConfigurationArtifact firstProfile = SignedConfigurationArtifact.From(
            profileCompiler.CompileAndSign(Profile("1.0.0")));
        SignedConfigurationArtifact secondProfile = SignedConfigurationArtifact.From(
            profileCompiler.CompileAndSign(Profile("1.1.0")));
        await configurationStore.AddDraftAsync(firstProfile, "author", token);
        await configurationStore.AddDraftAsync(secondProfile, "author", token);
        await configurationStore.ApproveAsync("tenant-a", firstProfile.Kind,
            firstProfile.ArtifactId, firstProfile.Version, "reviewer-a", token);
        await configurationStore.ApproveAsync("tenant-a", firstProfile.Kind,
            firstProfile.ArtifactId, firstProfile.Version, "reviewer-b", token);
        await configurationStore.PromoteAsync("tenant-a", firstProfile.Kind,
            firstProfile.ArtifactId, firstProfile.Version, SignedConfigurationStage.Enforced,
            0, "operator", token);
        await configurationStore.ApproveAsync("tenant-a", secondProfile.Kind,
            secondProfile.ArtifactId, secondProfile.Version, "reviewer-a", token);
        await configurationStore.PromoteAsync("tenant-a", secondProfile.Kind,
            secondProfile.ArtifactId, secondProfile.Version, SignedConfigurationStage.Canary,
            10, "operator", token);
        SignedConfigurationDeployment restored = await configurationStore.RollbackAsync(
            "tenant-a", secondProfile.Kind, "game", "test", "operator", token);
        Assert.Equal("1.0.0", restored.Artifact.Version);
        await Assert.ThrowsAsync<SignedConfigurationException>(async () =>
            await configurationStore.GetAsync("tenant-b", firstProfile.Kind,
                firstProfile.ArtifactId, firstProfile.Version, token));

        var buildRegistry = new PostgresAgentBuildRegistry(dataSource, TimeProvider.System);
        await buildRegistry.RegisterAsync("tenant-a", "game", "test", "build-1",
            "release-operator", [1], token);
        Assert.True(await buildRegistry.IsApprovedAsync("tenant-a", "game", "test",
            "build-1", token));
        Assert.False(await buildRegistry.IsApprovedAsync("tenant-b", "game", "test",
            "build-1", token));
        Assert.True(await buildRegistry.RevokeAsync("tenant-a", "game", "test", "build-1",
            "release-operator", token));
        Assert.False(await buildRegistry.IsApprovedAsync("tenant-a", "game", "test",
            "build-1", token));

        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(token);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(token);
        await using (var create = new NpgsqlCommand(
            "CREATE TABLE IF NOT EXISTS certael_test_game_state(id int PRIMARY KEY, value int NOT NULL); " +
            "INSERT INTO certael_test_game_state VALUES (1,0) ON CONFLICT (id) DO UPDATE SET value=0", connection, transaction))
            await create.ExecuteNonQueryAsync(token);
        await using (var mutate = new NpgsqlCommand("UPDATE certael_test_game_state SET value=1 WHERE id=1", connection, transaction))
            await mutate.ExecuteNonQueryAsync(token);
        var authoritative = new PostgresAuthoritativeTransaction<int>(connection, transaction, 1, 0,
            "tenant-a", "game", "test", "session-a");
        Guid actionId = Guid.NewGuid();
        Assert.True((await authoritative.ReserveActionAsync<string>(actionId, token)).Reserved);
        authoritative.EnqueueAuthoritativeEvent(new AuthoritativeEvent(Guid.NewGuid(), actionId,
            "inventory.crafted", 1, new byte[] { 1 }, DateTimeOffset.UtcNow));
        await authoritative.StageActionResultAsync(ActionResult<string>.Accept(actionId, "created", 1), token);
        await authoritative.CommitAsync(token);
        await authoritative.DisposeAsync();

        await using NpgsqlCommand verifyOutbox = dataSource.CreateCommand(
            "SELECT (SELECT value FROM certael_test_game_state WHERE id=1), " +
            "(SELECT count(*) FROM certael_outbox WHERE session_id='session-a' AND action_id=$1)");
        verifyOutbox.Parameters.AddWithValue(actionId);
        await using NpgsqlDataReader outboxReader = await verifyOutbox.ExecuteReaderAsync(token);
        Assert.True(await outboxReader.ReadAsync(token));
        Assert.Equal(1, outboxReader.GetInt32(0)); Assert.Equal(1L, outboxReader.GetInt64(1));
        await outboxReader.DisposeAsync();

        var publisher = new RecordingPublisher();
        Assert.Equal(1, await new PostgresOutboxDispatcher(dataSource, publisher, "tenant-a").DispatchBatchAsync(10, token));
        Assert.Single(publisher.Messages);
        Assert.Equal(actionId, publisher.Messages[0].ActionId);
        Assert.Equal(0, await new PostgresOutboxDispatcher(dataSource, publisher, "tenant-a").DispatchBatchAsync(10, token));

        await using (NpgsqlConnection duplicateConnection = await dataSource.OpenConnectionAsync(token))
        await using (NpgsqlTransaction duplicateTransaction = await duplicateConnection.BeginTransactionAsync(token))
        await using (var duplicate = new PostgresAuthoritativeTransaction<int>(duplicateConnection,
            duplicateTransaction, 1, 1, "tenant-a", "game", "test", "session-a"))
        {
            ActionReservation<string> reservation = await duplicate.ReserveActionAsync<string>(actionId, token);
            Assert.False(reservation.Reserved);
            Assert.Equal("created", reservation.ExistingResult?.Response);
        }

        Guid rolledBackAction = Guid.NewGuid();
        await using (NpgsqlConnection rollbackConnection = await dataSource.OpenConnectionAsync(token))
        await using (NpgsqlTransaction rollbackTransaction = await rollbackConnection.BeginTransactionAsync(token))
        await using (var rollback = new PostgresAuthoritativeTransaction<int>(rollbackConnection,
            rollbackTransaction, 2, 1, "tenant-a", "game", "test", "session-a"))
        {
            Assert.True((await rollback.ReserveActionAsync<string>(rolledBackAction, token)).Reserved);
            await using var mutateAgain = new NpgsqlCommand(
                "UPDATE certael_test_game_state SET value=2 WHERE id=1", rollbackConnection, rollbackTransaction);
            await mutateAgain.ExecuteNonQueryAsync(token);
            rollback.EnqueueAuthoritativeEvent(new AuthoritativeEvent(Guid.NewGuid(), rolledBackAction,
                "inventory.crafted", 1, new byte[] { 2 }, DateTimeOffset.UtcNow));
            await rollback.StageActionResultAsync(ActionResult<string>.Accept(rolledBackAction, "rolled-back", 2), token);
            // Deliberately dispose without commit to simulate a failed worker.
        }
        await using (NpgsqlCommand rollbackVerify = dataSource.CreateCommand(
            "SELECT (SELECT value FROM certael_test_game_state WHERE id=1), " +
            "(SELECT count(*) FROM certael_action_results WHERE action_id=$1), " +
            "(SELECT count(*) FROM certael_outbox WHERE action_id=$1)"))
        {
            rollbackVerify.Parameters.AddWithValue(rolledBackAction);
            await using NpgsqlDataReader reader = await rollbackVerify.ExecuteReaderAsync(token);
            Assert.True(await reader.ReadAsync(token));
            Assert.Equal(1, reader.GetInt32(0)); Assert.Equal(0L, reader.GetInt64(1)); Assert.Equal(0L, reader.GetInt64(2));
        }

        var actionResults = new PostgresActionResultStore(dataSource);
        var result = ActionResult<string>.Accept(actionId, "created", 1);
        await actionResults.StoreAsync("tenant-a", "session-a", result, token);
        Assert.Equal(result, await actionResults.FindAsync<string>("tenant-a", "session-a", actionId, token));
        Assert.Null(await actionResults.FindAsync<string>("tenant-a", "other-session", actionId, token));

        Finding finding = FindingFor("tenant-a", "player");
        var engine = new VerdictEngine(TimeProvider.System);
        Verdict verdict = engine.Evaluate([finding]);
        EvidenceBundle bundle = EvidenceReplay.Create(verdict, [finding]);
        var evidence = new PostgresEvidenceStore(dataSource, TimeSpan.FromDays(1));
        await evidence.SaveAsync(bundle, token);
        Assert.NotNull(await evidence.FindAsync("tenant-a", verdict.VerdictId, token));
        Assert.Null(await evidence.FindAsync("tenant-b", verdict.VerdictId, token));
        await AssertRestrictedRoleRls(dataSource, token);
        AgentPlayerDeletionResult deletion = await agentStore.DeletePlayerAsync(
            "tenant-a", "test", "player", token);
        Assert.Equal(1, deletion.SessionsDeleted);
        Assert.Equal(1, deletion.RawReportsDeleted);
        Assert.Null(await agentStore.HealthAsync("tenant-a", "agent-a", token));
        await evidence.DeletePlayerAsync("tenant-a", "test", "player", token);
        Assert.Null(await evidence.FindAsync("tenant-a", verdict.VerdictId, token));
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task RedisProvidesDistributedSingleUseAndMonotonicSequence()
    {
        string? configuration = Environment.GetEnvironmentVariable("CERTAEL_TEST_REDIS");
        if (configuration is null) { Assert.Skip("CERTAEL_TEST_REDIS is not configured."); return; }
        CancellationToken token = TestContext.Current.CancellationToken;
        await using ConnectionMultiplexer redis = await ConnectionMultiplexer.ConnectAsync(configuration);
        string prefix = "test-" + Guid.NewGuid().ToString("N");
        var tickets = new RedisTicketRedemptionStore(redis, prefix);
        Guid id = Guid.NewGuid();
        Assert.True(await tickets.TryRedeemAsync("tenant-a", "test", id,
            DateTimeOffset.UtcNow.AddMinutes(1), token));
        Assert.False(await tickets.TryRedeemAsync("tenant-a", "test", id,
            DateTimeOffset.UtcNow.AddMinutes(1), token));
        Assert.True(await tickets.TryRedeemAsync("tenant-b", "test", id,
            DateTimeOffset.UtcNow.AddMinutes(1), token));

        var sequences = new RedisSequenceStore(redis, TimeSpan.FromMinutes(1), prefix);
        byte[] zero = new byte[32];
        byte[] first = SHA256.HashData("first"u8);
        byte[] second = SHA256.HashData("second"u8);
        var policy = new ActionAdmissionPolicy(10, TimeSpan.FromMinutes(1));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Assert.True((await sequences.TryAdmitAsync(new("session", "test", 10, zero, first, now,
            InitialSequence: 10), policy, token)).Allowed);
        Assert.Equal("REPLAY_OR_REORDER", (await sequences.TryAdmitAsync(new("session", "test", 10,
            first, second, now, InitialSequence: 10), policy, token)).PublicReason);
        Assert.Equal("REPLAY_OR_REORDER", (await sequences.TryAdmitAsync(new("session", "test", 9,
            first, second, now, InitialSequence: 10), policy, token)).PublicReason);
        Assert.Equal("SEQUENCE_GAP", (await sequences.TryAdmitAsync(new("session", "test", 12,
            first, second, now, InitialSequence: 10), policy, token)).PublicReason);
        Assert.True((await sequences.TryAdmitAsync(new("session", "test", 11, first, second, now,
            InitialSequence: 10), policy, token)).Allowed);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ApiRedeemptionPersistsActiveSessionWhenConfiguredForProductionStores()
    {
        string? postgres = Environment.GetEnvironmentVariable("CERTAEL_TEST_POSTGRES");
        string? redis = Environment.GetEnvironmentVariable("CERTAEL_TEST_REDIS");
        if (postgres is null || redis is null) { Assert.Skip("Persistence services are not configured."); return; }
        CancellationToken token = TestContext.Current.CancellationToken;
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(web =>
        {
            web.UseSetting("ConnectionStrings:Postgres", postgres);
            web.UseSetting("ConnectionStrings:Redis", redis);
        });
        using HttpClient client = factory.CreateClient();
        BootstrapTicketSigner signer = factory.Services.GetRequiredService<BootstrapTicketSigner>();
        using Key ephemeral = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving });
        byte[] publicKey = ephemeral.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var claims = new BootstrapTicketClaims("https://certael.local", "certael-session", Guid.NewGuid(),
            "api-tenant", "game", "test", "api-player", "api-match", "server", "build", "competitive",
            publicKey, now, now, now.AddSeconds(60), 1, 1);
        SignedBootstrapTicket ticket = signer.Issue(claims, now);
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] proof = SignatureAlgorithm.Ed25519.Sign(ephemeral,
            BootstrapTicketValidator.CreateRedemptionMessage(claims.TicketId, challenge));

        using HttpResponseMessage response = await client.PostAsJsonAsync("/v1/sessions/redeem",
            new RedeemTicketRequest(ticket, publicKey, challenge, proof), token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        ActiveSessionResponse? active = await response.Content.ReadFromJsonAsync<ActiveSessionResponse>(token);
        Assert.NotNull(active);
        PostgresSessionStore store = factory.Services.GetRequiredService<PostgresSessionStore>();
        SessionAuthorization? persisted = await store.FindAsync("api-tenant", active.SessionId, token);
        Assert.NotNull(persisted);
        Assert.Equal("api-tenant", persisted.TenantId);
        Assert.Equal("api-match", persisted.MatchId);

        using HttpResponseMessage configurationAdmin = await client.PostAsJsonAsync(
            "/v1/admin/configurations/drafts", new SignedConfigurationDraftRequest(
                SignedConfigurationKind.ProtectionProfile, "api-tenant", "profile", "1.0.0",
                "game", "test", [1], new byte[32], new byte[64], "key", "test"), token);
        Assert.Equal(HttpStatusCode.Unauthorized, configurationAdmin.StatusCode);
    }

    private static async Task ResetPostgres(NpgsqlDataSource source, CancellationToken token)
    {
        await using NpgsqlCommand command = source.CreateCommand(
            "TRUNCATE certael_agent_builds, certael_ticket_redemptions, " +
            "certael_signed_configuration_active, certael_signed_configuration_approvals, " +
            "certael_signed_configurations, " +
            "certael_agent_policy_approvals, certael_agent_policies, " +
            "certael_agent_reports, certael_agent_sessions, certael_action_results, " +
            "certael_outbox, certael_evidence, certael_sessions CASCADE");
        await command.ExecuteNonQueryAsync(token);
    }

    private static async Task AssertRestrictedRoleRls(NpgsqlDataSource source, CancellationToken token)
    {
        await using (NpgsqlCommand setup = source.CreateCommand("""
            DO $$ BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='certael_rls_test') THEN
                CREATE ROLE certael_rls_test NOLOGIN NOSUPERUSER NOBYPASSRLS;
              END IF;
            END $$;
            GRANT USAGE ON SCHEMA public TO certael_rls_test;
            GRANT SELECT, UPDATE ON certael_sessions TO certael_rls_test;
            GRANT SELECT, UPDATE ON certael_agent_sessions TO certael_rls_test;
            GRANT SELECT ON certael_agent_reports TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_agent_policies TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_agent_policy_approvals TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_ticket_redemptions TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_agent_builds TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_signed_configurations TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_signed_configuration_approvals TO certael_rls_test;
            GRANT SELECT, INSERT, UPDATE ON certael_signed_configuration_active TO certael_rls_test;
            """))
            await setup.ExecuteNonQueryAsync(token);

        await using NpgsqlConnection connection = await source.OpenConnectionAsync(token);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(token);
        await using (var role = new NpgsqlCommand("SET LOCAL ROLE certael_rls_test", connection, transaction))
            await role.ExecuteNonQueryAsync(token);
        await using (var tenant = new NpgsqlCommand(
            "SELECT set_config('certael.tenant_id','tenant-a',true)", connection, transaction))
            await tenant.ExecuteNonQueryAsync(token);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_sessions", connection, transaction))
            Assert.Equal(1L, (long)(await read.ExecuteScalarAsync(token))!);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_agent_sessions", connection, transaction))
            Assert.Equal(1L, (long)(await read.ExecuteScalarAsync(token))!);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_agent_policies", connection, transaction))
            Assert.Equal(1L, (long)(await read.ExecuteScalarAsync(token))!);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_ticket_redemptions", connection, transaction))
            Assert.Equal(1L, (long)(await read.ExecuteScalarAsync(token))!);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_agent_builds", connection, transaction))
            Assert.Equal(1L, (long)(await read.ExecuteScalarAsync(token))!);
        await using (var read = new NpgsqlCommand("SELECT count(*) FROM certael_signed_configurations", connection, transaction))
            Assert.Equal(2L, (long)(await read.ExecuteScalarAsync(token))!);
        await using var crossWrite = new NpgsqlCommand(
            "UPDATE certael_sessions SET tenant_id='tenant-b' WHERE session_id='session-a'", connection, transaction);
        PostgresException exception = await Assert.ThrowsAsync<PostgresException>(async () =>
            await crossWrite.ExecuteNonQueryAsync(token));
        Assert.Equal("42501", exception.SqlState);
    }

    private static Finding FindingFor(string tenant, string player) =>
        new(Guid.NewGuid(), tenant, "game", "test", "session-a", player, "inventory.rule", "1.0.0",
            new byte[32], null, SignalFamily.AuthoritativeContradiction, FindingTrust.Authoritative,
            50, 1, DateTimeOffset.UtcNow,
            ImmutableArray.Create(new EvidenceField("reason", "test", Provenance.CertaelDerived)));

    private sealed class RecordingPublisher : IOutboxPublisher
    {
        public List<OutboxMessage> Messages { get; } = [];
        public ValueTask PublishAsync(OutboxMessage message, CancellationToken cancellationToken)
        { Messages.Add(message); return ValueTask.CompletedTask; }
    }
}

[CollectionDefinition("Persistence", DisableParallelization = true)]
public sealed class PersistenceCollection;

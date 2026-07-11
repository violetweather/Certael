using System.Collections.Immutable;
using Certael.Persistence.Postgres;
using Certael.Persistence.Redis;
using Certael.Server.Actions;
using Certael.Server.Evidence;
using Certael.Server.Sessions;
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

        var session = new SessionAuthorization("session-a", "tenant-a", "game", "test", "player", "match",
            "server", "build", DateTimeOffset.UtcNow.AddMinutes(30), 1, 1000, new byte[32]);
        var sessions = new PostgresSessionStore(dataSource);
        await sessions.CreateAsync(session, token);
        SessionAuthorization? persistedSession = await sessions.FindAsync(session.SessionId, token);
        Assert.NotNull(persistedSession);
        Assert.Equal(session.SessionId, persistedSession.SessionId);
        Assert.Equal(session.TenantId, persistedSession.TenantId);
        Assert.Equal(session.EphemeralPublicKey.ToArray(), persistedSession.EphemeralPublicKey.ToArray());
        DateTimeOffset renewedExpiry = DateTimeOffset.UtcNow.AddHours(1);
        Assert.False(await sessions.RenewAsync("session-a", "wrong-server", renewedExpiry, token));
        Assert.True(await sessions.RenewAsync("session-a", "server", renewedExpiry, token));
        Assert.Equal(renewedExpiry.ToUnixTimeSeconds(),
            (await sessions.FindAsync("session-a", token))!.ExpiresAt.ToUnixTimeSeconds());

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
        Assert.Equal(1, await new PostgresOutboxDispatcher(dataSource, publisher).DispatchBatchAsync(10, token));
        Assert.Single(publisher.Messages);
        Assert.Equal(actionId, publisher.Messages[0].ActionId);
        Assert.Equal(0, await new PostgresOutboxDispatcher(dataSource, publisher).DispatchBatchAsync(10, token));

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
        await actionResults.StoreAsync("session-a", result, token);
        Assert.Equal(result, await actionResults.FindAsync<string>("session-a", actionId, token));
        Assert.Null(await actionResults.FindAsync<string>("other-session", actionId, token));

        Finding finding = FindingFor("tenant-a", "player");
        var engine = new VerdictEngine(TimeProvider.System);
        Verdict verdict = engine.Evaluate([finding]);
        EvidenceBundle bundle = EvidenceReplay.Create(verdict, [finding]);
        var evidence = new PostgresEvidenceStore(dataSource, TimeSpan.FromDays(1));
        await evidence.SaveAsync(bundle, token);
        Assert.NotNull(await evidence.FindAsync("tenant-a", verdict.VerdictId, token));
        Assert.Null(await evidence.FindAsync("tenant-b", verdict.VerdictId, token));
        await evidence.DeletePlayerAsync("tenant-a", "player", token);
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
        Assert.True(await tickets.TryRedeemAsync(id, DateTimeOffset.UtcNow.AddMinutes(1), token));
        Assert.False(await tickets.TryRedeemAsync(id, DateTimeOffset.UtcNow.AddMinutes(1), token));

        var sequences = new RedisSequenceStore(redis, TimeSpan.FromMinutes(1), prefix);
        byte[] zero = new byte[32];
        byte[] first = SHA256.HashData("first"u8);
        byte[] second = SHA256.HashData("second"u8);
        var policy = new ActionAdmissionPolicy(10, TimeSpan.FromMinutes(1));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Assert.True((await sequences.TryAdmitAsync(new("session", "test", 10, zero, first, now), policy, token)).Allowed);
        Assert.Equal("REPLAY_OR_REORDER", (await sequences.TryAdmitAsync(new("session", "test", 10, first, second, now), policy, token)).PublicReason);
        Assert.Equal("REPLAY_OR_REORDER", (await sequences.TryAdmitAsync(new("session", "test", 9, first, second, now), policy, token)).PublicReason);
        Assert.True((await sequences.TryAdmitAsync(new("session", "test", 11, first, second, now), policy, token)).Allowed);
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
        SessionAuthorization? persisted = await store.FindAsync(active.SessionId, token);
        Assert.NotNull(persisted);
        Assert.Equal("api-tenant", persisted.TenantId);
        Assert.Equal("api-match", persisted.MatchId);
    }

    private static async Task ResetPostgres(NpgsqlDataSource source, CancellationToken token)
    {
        await using NpgsqlCommand command = source.CreateCommand(
            "TRUNCATE certael_action_results, certael_outbox, certael_evidence, certael_sessions CASCADE");
        await command.ExecuteNonQueryAsync(token);
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

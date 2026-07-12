using System.Security.Cryptography;
using System.Security.Claims;
using Certael.Server.Sessions;
using Certael.Server.Actions;
using Certael.Persistence.Postgres;
using Certael.Persistence.Redis;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Npgsql;
using StackExchange.Redis;
using Certael.Api.Security;
using Certael.Server.Audit;
using Certael.Server.Diagnostics;
using System.Text;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
bool exportOtlp = !string.IsNullOrWhiteSpace(
    builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]);
builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource.AddService("certael-api"))
    .WithTracing(tracing =>
    {
        tracing.AddSource(CertaelTelemetry.SourceName).AddAspNetCoreInstrumentation(options =>
        {
            options.Filter = context => !context.Request.Path.StartsWithSegments("/livez")
                && !context.Request.Path.StartsWithSegments("/readyz");
        });
        if (exportOtlp) tracing.AddOtlpExporter();
    })
    .WithMetrics(metrics =>
    {
        metrics.AddMeter(CertaelTelemetry.SourceName).AddAspNetCoreInstrumentation()
            .AddRuntimeInstrumentation();
        if (exportOtlp) metrics.AddOtlpExporter();
    });
builder.Logging.AddOpenTelemetry(logging =>
{
    logging.IncludeFormattedMessage = true;
    logging.IncludeScopes = true;
    if (exportOtlp) logging.AddOtlpExporter();
});
builder.WebHost.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https =>
    https.ClientCertificateMode = ClientCertificateMode.AllowCertificate));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"];
    options.Audience = builder.Configuration["Authentication:Audience"] ?? "certael-api";
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("session-redemption", http => RateLimitPartition.GetFixedWindowLimiter(
        http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 20, Window = TimeSpan.FromMinutes(1), QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("service-operations", http => RateLimitPartition.GetFixedWindowLimiter(
        $"{http.User.FindFirstValue("sub") ?? "anonymous"}|{http.User.FindFirstValue("tenant_id") ?? "unknown"}|{http.User.FindFirstValue("environment_id") ?? "unknown"}",
        _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 600, Window = TimeSpan.FromMinutes(1), QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("administration", http => RateLimitPartition.GetFixedWindowLimiter(
        $"{http.User.FindFirstValue("sub") ?? "anonymous"}|{http.Connection.RemoteIpAddress}",
        _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 60, Window = TimeSpan.FromMinutes(1), QueueLimit = 0,
            AutoReplenishment = true
        }));
});
builder.Services.AddSingleton(TimeProvider.System);
ConfigurePersistence(builder);
string ticketIssuer = RequiredSetting(builder.Configuration, builder.Environment,
    "Signing:Issuer", "https://certael.local");
string ticketAudience = RequiredSetting(builder.Configuration, builder.Environment,
    "Signing:Audience", "certael-session");
builder.Services.AddSingleton(_ => LoadSigningKeyRing(builder.Configuration, builder.Environment));
builder.Services.AddSingleton(sp => new BootstrapTicketSigner(
    sp.GetRequiredService<BootstrapSigningKeyRing>()));
builder.Services.AddSingleton(sp => new BootstrapTicketValidator(
    sp.GetRequiredService<BootstrapSigningKeyRing>(), ticketIssuer, ticketAudience,
    sp.GetRequiredService<ITicketRedemptionStore>(), sp.GetRequiredService<TimeProvider>()));

WebApplication app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Cache-Control"] = "no-store";
    context.Response.Headers["X-Certael-Request-Id"] = context.TraceIdentifier;
    await next();
});

app.MapHealthChecks("/healthz");
app.MapGet("/livez", () => Results.Ok(new { status = "live" }));
app.MapGet("/readyz", async (IServiceProvider services, CancellationToken cancellationToken) =>
{
    if (services.GetService<NpgsqlDataSource>() is { } postgres)
    {
        await using NpgsqlConnection connection = await postgres.OpenConnectionAsync(cancellationToken);
        await using NpgsqlCommand command = new("SELECT 1", connection);
        await command.ExecuteScalarAsync(cancellationToken);
    }
    if (services.GetService<IConnectionMultiplexer>() is { } redis)
        await redis.GetDatabase().PingAsync();
    return Results.Ok(new { status = "ready" });
});
app.MapPost("/v1/sessions/redeem", async (
    RedeemTicketRequest request,
    BootstrapTicketValidator validator,
    TimeProvider clock,
    ISessionAuthorizationWriter sessions,
    CancellationToken cancellationToken) =>
{
    if (request.Ticket is null || request.Ticket.Claims is null
        || request.Ticket.Signature is null || request.Ticket.KeyId is null
        || request.EphemeralPublicKey is null || request.Challenge is null
        || request.PossessionSignature is null)
        return Results.Json(new { error = "INVALID_TICKET" },
            statusCode: StatusCodes.Status401Unauthorized);
    TicketValidationResult validation = await validator.ValidateAndRedeemAsync(
        request.Ticket, request.EphemeralPublicKey, request.Challenge,
        request.PossessionSignature, cancellationToken);
    if (!validation.Valid)
    {
        CertaelTelemetry.RecordSession("redeem", validation.PublicReason, "unknown", "unknown");
        return Results.Json(new { error = validation.PublicReason }, statusCode: StatusCodes.Status401Unauthorized);
    }

    BootstrapTicketClaims claims = validation.Claims!;
    string sessionId = Guid.NewGuid().ToString("N");
    DateTimeOffset now = clock.GetUtcNow();
    DateTimeOffset expiresAt = now.AddMinutes(30);
    DateTimeOffset absoluteExpiresAt = now.AddHours(8);
    var activeSession = new SessionAuthorization(
        sessionId, claims.TenantId, claims.GameId, claims.EnvironmentId, claims.PlayerSubject,
        claims.MatchId, claims.AuthoritativeServerId, claims.BuildId, expiresAt, 1,
        1_000_000_000, claims.EphemeralPublicKey, absoluteExpiresAt, null, request.Ticket.KeyId,
        claims.ProtectionProfile, claims.ProtocolMinimum, claims.ProtocolMaximum);
    await sessions.CreateAsync(activeSession, cancellationToken);
    CertaelTelemetry.RecordSession("redeem", "accepted", claims.TenantId, claims.EnvironmentId);
    return Results.Ok(new ActiveSessionResponse(
        sessionId, claims.GameId, claims.EnvironmentId,
        claims.PlayerSubject, claims.MatchId, claims.AuthoritativeServerId,
        claims.BuildId, expiresAt, 1, SessionBindingDigest.Compute(activeSession),
        claims.ProtocolMinimum, claims.ProtocolMaximum, claims.ProtectionProfile));
}).RequireRateLimiting("session-redemption");
app.MapPost("/v1/sessions/{sessionId}/renew", async (
    string sessionId,
    RenewSessionRequest request,
    HttpContext http,
    ISessionAuthorizationStore sessions,
    ISessionAuthorizationWriter writer,
    TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(
        http.User, http.Connection.ClientCertificate, "sessions:renew",
        request.TenantId, request.EnvironmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    SessionAuthorization? session = await sessions.FindAsync(request.TenantId, sessionId, cancellationToken);
    if (session is null || session.TenantId != request.TenantId
        || session.EnvironmentId != request.EnvironmentId
        || session.AuthoritativeServerId != request.AuthoritativeServerId)
        return Results.NotFound();
    DateTimeOffset expiresAt = clock.GetUtcNow().AddMinutes(30);
    bool renewed = await writer.RenewAsync(request.TenantId, sessionId,
        request.AuthoritativeServerId, expiresAt, cancellationToken);
    CertaelTelemetry.RecordSession("renew", renewed ? "accepted" : "conflict",
        request.TenantId, request.EnvironmentId);
    return renewed ? Results.Ok(new { sessionId, expiresAt }) : Results.Conflict();
}).RequireAuthorization().RequireRateLimiting("service-operations");
app.MapPost("/v1/sessions/{sessionId}/revoke", async (
    string sessionId,
    RevokeSessionRequest request,
    HttpContext http,
    ISessionAuthorizationStore sessions,
    ISessionAuthorizationWriter writer,
    IAuditStore audit,
    TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    if (!ValidReason(request.Reason))
        return Results.BadRequest(new { error = "INVALID_REASON" });
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(
        http.User, http.Connection.ClientCertificate, "sessions:revoke",
        request.TenantId, request.EnvironmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    SessionAuthorization? session = await sessions.FindAsync(request.TenantId, sessionId, cancellationToken);
    if (session is null || session.TenantId != request.TenantId
        || session.EnvironmentId != request.EnvironmentId
        || session.AuthoritativeServerId != request.AuthoritativeServerId)
        return Results.NotFound();
    DateTimeOffset now = clock.GetUtcNow();
    bool revoked = await writer.RevokeAsync(request.TenantId, sessionId, request.AuthoritativeServerId,
        now, cancellationToken);
    await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), request.TenantId, request.EnvironmentId,
        http.User.FindFirstValue("sub") ?? "unknown", "session.revoke", "session", sessionId,
        request.Reason, null, null, http.TraceIdentifier, now, revoked,
        http.Connection.RemoteIpAddress?.ToString(),
        http.User.FindFirstValue("sub") ?? "unknown"), cancellationToken);
    CertaelTelemetry.RecordSession("revoke", revoked ? "accepted" : "conflict",
        request.TenantId, request.EnvironmentId);
    return revoked ? Results.NoContent() : Results.Conflict();
}).RequireAuthorization().RequireRateLimiting("service-operations");
app.MapPost("/v1/admin/sessions/revoke", async (
    BulkRevokeSessionsRequest request,
    HttpContext http,
    ISessionAdministrationStore sessions,
    IAuditStore audit,
    TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    if (!ValidReason(request.Reason))
        return Results.BadRequest(new { error = "INVALID_REASON" });
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(http.User,
        http.Connection.ClientCertificate, "sessions:revoke:bulk",
        request.TenantId, request.EnvironmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    var selector = new SessionRevocationSelector(request.TenantId, request.EnvironmentId,
        request.GameId, request.BuildId, request.SigningKeyId, request.AuthoritativeServerId);
    DateTimeOffset now = clock.GetUtcNow();
    int revoked = await sessions.RevokeMatchingAsync(selector, now, cancellationToken);
    string selectorText = string.Join('|', request.TenantId, request.EnvironmentId,
        request.GameId ?? "*", request.BuildId ?? "*", request.SigningKeyId ?? "*",
        request.AuthoritativeServerId ?? "*");
    string afterDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{selectorText}|{revoked}|{now.ToUnixTimeSeconds()}"))).ToLowerInvariant();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), request.TenantId,
        request.EnvironmentId, subject, "session.revoke.bulk", "session-selector",
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(selectorText))).ToLowerInvariant(),
        request.Reason, null, afterDigest, http.TraceIdentifier, now, true,
        http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
    CertaelTelemetry.RecordSession("revoke_bulk", "accepted", request.TenantId,
        request.EnvironmentId);
    return Results.Ok(new { revoked });
}).RequireAuthorization().RequireRateLimiting("administration");
app.MapGet("/v1/audit", async (string tenantId, string environmentId, int? maximum,
    HttpContext http, IAuditStore audit, CancellationToken cancellationToken) =>
{
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(http.User,
        http.Connection.ClientCertificate, "audit:read", tenantId, environmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    return Results.Ok(await audit.RecentAsync(tenantId, environmentId,
        Math.Clamp(maximum ?? 100, 1, 1000), cancellationToken));
}).RequireAuthorization().RequireRateLimiting("administration");
app.MapPost("/v1/sessions/tickets", (
    IssueTicketRequest request,
    BootstrapTicketSigner signer,
    TimeProvider clock,
    HttpContext http) =>
{
    if (request.EphemeralPublicKey is null)
        return Results.BadRequest(new { error = "INVALID_TICKET_REQUEST" });
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(
        http.User, http.Connection.ClientCertificate, "sessions:issue",
        request.TenantId, request.EnvironmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    DateTimeOffset now = clock.GetUtcNow();
    var claims = new BootstrapTicketClaims(
        ticketIssuer, ticketAudience, Guid.NewGuid(),
        request.TenantId, request.GameId, request.EnvironmentId,
        request.PlayerSubject, request.MatchId, request.ServerId, request.BuildId,
        request.ProtectionProfile, request.EphemeralPublicKey,
        now, now, now.AddSeconds(60), 1, 1);
    try
    {
        SignedBootstrapTicket ticket = signer.Issue(claims, now);
        CertaelTelemetry.RecordSession("issue", "accepted", request.TenantId, request.EnvironmentId);
        return Results.Ok(ticket);
    }
    catch (Exception exception) when (exception is ArgumentException or TicketClaimsException)
    {
        return Results.BadRequest(new { error = "INVALID_TICKET_REQUEST" });
    }
}).RequireAuthorization().RequireRateLimiting("service-operations");

if (app.Services.GetService<NpgsqlDataSource>() is { } dataSource)
    await new PostgresMigrationRunner(dataSource).ApplyAsync();

app.Run();

static BootstrapSigningKeyRing LoadSigningKeyRing(
    IConfiguration configuration, IHostEnvironment environment)
{
    string keyId = RequiredSetting(configuration, environment,
        "Signing:ActiveKeyId", "development-key");
    IConfigurationSection[] configuredKeys = configuration.GetSection("Signing:Keys")
        .GetChildren().ToArray();
    if (configuredKeys.Length > 0)
    {
        var keys = new List<BootstrapSigningKey>(configuredKeys.Length);
        try
        {
            foreach (IConfigurationSection item in configuredKeys)
            {
                string configuredId = item["KeyId"]
                    ?? throw new InvalidOperationException("Every Signing:Keys entry requires KeyId.");
                string pemPath = item["PemPath"]
                    ?? throw new InvalidOperationException($"Signing key {configuredId} requires PemPath.");
                if (!DateTimeOffset.TryParse(item["NotBefore"], out DateTimeOffset notBefore)
                    || !DateTimeOffset.TryParse(item["NotAfter"], out DateTimeOffset notAfter))
                    throw new InvalidOperationException($"Signing key {configuredId} requires valid NotBefore/NotAfter values.");
                var material = ECDsa.Create();
                try { material.ImportFromPem(File.ReadAllText(pemPath)); }
                catch { material.Dispose(); throw; }
                keys.Add(new BootstrapSigningKey(configuredId, material, notBefore, notAfter,
                    item.GetValue("Revoked", false), item["Usage"] ?? "ticket-signing",
                    item["TenantId"] ?? "*", item["EnvironmentId"] ?? "*"));
            }
            return new BootstrapSigningKeyRing(keys, keyId);
        }
        catch
        {
            foreach (ECDsa material in keys.Select(value => value.Key)) material.Dispose();
            throw;
        }
    }
    string? path = configuration["Signing:PrivateKeyPemPath"];
    ECDsa key;
    if (string.IsNullOrWhiteSpace(path))
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException("Signing:PrivateKeyPemPath is required outside Development.");
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }
    else
    {
        key = ECDsa.Create();
        try { key.ImportFromPem(File.ReadAllText(path)); }
        catch { key.Dispose(); throw; }
    }
    return new BootstrapSigningKeyRing([
        new BootstrapSigningKey(keyId, key, DateTimeOffset.MinValue, DateTimeOffset.MaxValue,
            TenantId: configuration["Signing:TenantId"] ?? "*",
            EnvironmentId: configuration["Signing:EnvironmentId"] ?? "*")
    ], keyId);
}

static string RequiredSetting(IConfiguration configuration, IHostEnvironment environment,
    string key, string developmentDefault) =>
    !string.IsNullOrWhiteSpace(configuration[key]) ? configuration[key]!
    : environment.IsDevelopment() ? developmentDefault
    : throw new InvalidOperationException($"{key} is required outside Development.");

static bool ValidReason(string value) => !string.IsNullOrWhiteSpace(value)
    && value.Length <= 512 && !value.Any(char.IsControl);

static void ConfigurePersistence(WebApplicationBuilder builder)
{
    string? postgres = builder.Configuration.GetConnectionString("Postgres");
    string? redis = builder.Configuration.GetConnectionString("Redis");
    if (!string.IsNullOrWhiteSpace(postgres) && !string.IsNullOrWhiteSpace(redis))
    {
        builder.Services.AddSingleton(NpgsqlDataSource.Create(postgres));
        builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redis));
        builder.Services.AddSingleton<ITicketRedemptionStore, RedisTicketRedemptionStore>();
        builder.Services.AddSingleton<PostgresSessionStore>();
        builder.Services.AddSingleton<ISessionAuthorizationStore>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<ISessionAuthorizationWriter>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<ISessionAdministrationStore>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<IAuditStore, PostgresAuditStore>();
        return;
    }
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException("Postgres and Redis connection strings are required outside Development.");
    builder.Services.AddSingleton<ITicketRedemptionStore, InMemoryTicketRedemptionStore>();
    builder.Services.AddSingleton<InMemorySessionAuthorizationStore>();
    builder.Services.AddSingleton<ISessionAuthorizationStore>(service => service.GetRequiredService<InMemorySessionAuthorizationStore>());
    builder.Services.AddSingleton<ISessionAuthorizationWriter>(service => service.GetRequiredService<InMemorySessionAuthorizationStore>());
    builder.Services.AddSingleton<ISessionAdministrationStore>(service => service.GetRequiredService<InMemorySessionAuthorizationStore>());
    builder.Services.AddSingleton<IAuditStore, InMemoryAuditStore>();
}

public sealed record IssueTicketRequest(
    string TenantId, string GameId, string EnvironmentId, string PlayerSubject,
    string MatchId, string ServerId, string BuildId, string ProtectionProfile,
    byte[] EphemeralPublicKey);

public sealed record RedeemTicketRequest(
    SignedBootstrapTicket Ticket,
    byte[] EphemeralPublicKey,
    byte[] Challenge,
    byte[] PossessionSignature);

public sealed record ActiveSessionResponse(
    string SessionId, string GameId, string EnvironmentId, string PlayerSubject,
    string MatchId, string ServerId, string BuildId, DateTimeOffset ExpiresAt,
    ulong InitialSequence,
    byte[] BindingDigest,
    uint ProtocolMinimum = 1,
    uint ProtocolMaximum = 1,
    string ProtectionProfileId = "legacy");

public sealed record RenewSessionRequest(
    string TenantId, string EnvironmentId, string AuthoritativeServerId);

public sealed record RevokeSessionRequest(
    string TenantId, string EnvironmentId, string AuthoritativeServerId, string Reason);

public sealed record BulkRevokeSessionsRequest(
    string TenantId, string EnvironmentId, string Reason, string? GameId = null,
    string? BuildId = null, string? SigningKeyId = null,
    string? AuthoritativeServerId = null);

public partial class Program;

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

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
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
});
builder.Services.AddSingleton(TimeProvider.System);
ConfigurePersistence(builder);
builder.Services.AddSingleton(_ => LoadSigningKey(builder.Configuration, builder.Environment));
builder.Services.AddSingleton(sp => new BootstrapTicketSigner(sp.GetRequiredService<ECDsa>(), "development-key"));
builder.Services.AddSingleton(sp => new BootstrapTicketValidator(
    sp.GetRequiredService<ECDsa>(), "development-key", "https://certael.local", "certael-session",
    sp.GetRequiredService<ITicketRedemptionStore>(), sp.GetRequiredService<TimeProvider>()));

WebApplication app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapHealthChecks("/healthz");
app.MapPost("/v1/sessions/redeem", async (
    RedeemTicketRequest request,
    BootstrapTicketValidator validator,
    TimeProvider clock,
    ISessionAuthorizationWriter sessions,
    CancellationToken cancellationToken) =>
{
    TicketValidationResult validation = await validator.ValidateAndRedeemAsync(
        request.Ticket, request.EphemeralPublicKey, request.Challenge,
        request.PossessionSignature, cancellationToken);
    if (!validation.Valid)
        return Results.Json(new { error = validation.PublicReason }, statusCode: StatusCodes.Status401Unauthorized);

    BootstrapTicketClaims claims = validation.Claims!;
    string sessionId = Guid.NewGuid().ToString("N");
    DateTimeOffset expiresAt = clock.GetUtcNow().AddMinutes(30);
    await sessions.CreateAsync(new SessionAuthorization(
        sessionId, claims.TenantId, claims.GameId, claims.EnvironmentId, claims.PlayerSubject,
        claims.MatchId, claims.AuthoritativeServerId, claims.BuildId, expiresAt, 1,
        1_000_000_000, claims.EphemeralPublicKey), cancellationToken);
    return Results.Ok(new ActiveSessionResponse(
        sessionId, claims.GameId, claims.EnvironmentId,
        claims.PlayerSubject, claims.MatchId, claims.AuthoritativeServerId,
        claims.BuildId, expiresAt, 1));
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
    SessionAuthorization? session = await sessions.FindAsync(sessionId, cancellationToken);
    if (session is null || session.TenantId != request.TenantId
        || session.EnvironmentId != request.EnvironmentId
        || session.AuthoritativeServerId != request.AuthoritativeServerId)
        return Results.NotFound();
    DateTimeOffset expiresAt = clock.GetUtcNow().AddMinutes(30);
    return await writer.RenewAsync(sessionId, request.AuthoritativeServerId, expiresAt, cancellationToken)
        ? Results.Ok(new { sessionId, expiresAt }) : Results.Conflict();
}).RequireAuthorization();
app.MapPost("/v1/sessions/tickets", (
    IssueTicketRequest request,
    BootstrapTicketSigner signer,
    TimeProvider clock,
    HttpContext http) =>
{
    bool developmentBypass = app.Environment.IsDevelopment()
        && app.Configuration.GetValue("Development:AllowInsecureServiceIdentity", false);
    if (!developmentBypass)
    {
        ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(
            http.User, http.Connection.ClientCertificate, "sessions:issue",
            request.TenantId, request.EnvironmentId);
        if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
        if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    }
    DateTimeOffset now = clock.GetUtcNow();
    var claims = new BootstrapTicketClaims(
        "https://certael.local", "certael-session", Guid.NewGuid(),
        request.TenantId, request.GameId, request.EnvironmentId,
        request.PlayerSubject, request.MatchId, request.ServerId, request.BuildId,
        request.ProtectionProfile, request.EphemeralPublicKey,
        now, now, now.AddSeconds(60), 1, 1);
    return Results.Ok(signer.Issue(claims, now));
}).RequireAuthorization();

if (app.Services.GetService<NpgsqlDataSource>() is { } dataSource)
    await new PostgresMigrationRunner(dataSource).ApplyAsync();

app.Run();

static ECDsa LoadSigningKey(IConfiguration configuration, IHostEnvironment environment)
{
    string? path = configuration["Signing:PrivateKeyPemPath"];
    if (string.IsNullOrWhiteSpace(path))
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException("Signing:PrivateKeyPemPath is required outside Development.");
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }
    var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(path));
    return key;
}

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
        return;
    }
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException("Postgres and Redis connection strings are required outside Development.");
    builder.Services.AddSingleton<ITicketRedemptionStore, InMemoryTicketRedemptionStore>();
    builder.Services.AddSingleton<InMemorySessionAuthorizationStore>();
    builder.Services.AddSingleton<ISessionAuthorizationStore>(service => service.GetRequiredService<InMemorySessionAuthorizationStore>());
    builder.Services.AddSingleton<ISessionAuthorizationWriter>(service => service.GetRequiredService<InMemorySessionAuthorizationStore>());
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
    ulong InitialSequence);

public sealed record RenewSessionRequest(
    string TenantId, string EnvironmentId, string AuthoritativeServerId);

public partial class Program;

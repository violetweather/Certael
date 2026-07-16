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
using Certael.Server.Agent;
using Certael.Server.Evidence;
using Certael.Server.Configuration;
using Certael.Server.Protections;
using Certael.Server.Rules;
using Certael.Server.Compatibility;
using System.Text;
using System.Text.Json;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using NSec.Cryptography;

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
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("service-operations", http => RateLimitPartition.GetFixedWindowLimiter(
        $"{http.User.FindFirstValue("sub") ?? "anonymous"}|{http.User.FindFirstValue("tenant_id") ?? "unknown"}|{http.User.FindFirstValue("environment_id") ?? "unknown"}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 600,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("administration", http => RateLimitPartition.GetFixedWindowLimiter(
        $"{http.User.FindFirstValue("sub") ?? "anonymous"}|{http.Connection.RemoteIpAddress}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp => LoadCompatibilityGate(builder.Configuration,
    builder.Environment, sp.GetRequiredService<TimeProvider>()));
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
builder.Services.AddSingleton(_ => LoadAgentGrantSigner(builder.Configuration, builder.Environment));
builder.Services.AddSingleton<AgentReportVerifier>();
builder.Services.AddSingleton<AgentApiLifecycle>();
builder.Services.AddSingleton<ISignedConfigurationVerifier>(_ =>
    LoadSignedConfigurationVerifier(builder.Configuration, builder.Environment));

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
app.MapGet("/v1/status/compatibility", (CompatibilityAdmissionGate compatibility) =>
{
    CompatibilityDecision decision = compatibility.Evaluate(CertaelProduct.Core,
        CertaelRelease.ProductVersion, CertaelRelease.ActionProtocolVersion);
    CertaelTelemetry.RecordCompatibility("core", CertaelRelease.ProductVersion,
        decision.State.ToString(), decision.PublicReason, decision.ManifestRevision);
    return Results.Ok(new
    {
        product = "core",
        version = CertaelRelease.ProductVersion,
        protocolVersion = CertaelRelease.ActionProtocolVersion,
        state = decision.State.ToString(),
        reason = decision.PublicReason,
        recommendedVersion = decision.RecommendedVersion,
        manifestRevision = decision.ManifestRevision,
        manifestExpiresAt = compatibility.ExpiresAt,
        allowsNewProtectedSession = decision.AllowsNewProtectedSession
    });
});
app.MapPost("/v1/admin/compatibility/check", (CompatibilityCheckRequest request,
    HttpContext http, CompatibilityAdmissionGate compatibility) =>
{
    IResult? denied = AuthorizeAdministration(http, "compatibility:read",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!Enum.TryParse(request.Product, true, out CertaelProduct product)
        || !Enum.IsDefined(product)) return Results.BadRequest(new { error = "INVALID_PRODUCT" });
    CompatibilityDecision decision = compatibility.Evaluate(product, request.Version,
        request.ProtocolVersion);
    CertaelTelemetry.RecordCompatibility(request.Product, request.Version,
        decision.State.ToString(), decision.PublicReason, decision.ManifestRevision);
    return Results.Ok(new
    {
        product = product.ToString(),
        request.Version,
        request.ProtocolVersion,
        state = decision.State.ToString(),
        reason = decision.PublicReason,
        recommendedVersion = decision.RecommendedVersion,
        manifestRevision = decision.ManifestRevision,
        allowsNewProtectedSession = decision.AllowsNewProtectedSession
    });
}).RequireAuthorization().RequireRateLimiting("administration");
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

app.MapPost("/v1/agent/sessions", async (HttpContext http, AgentApiLifecycle lifecycle,
    CompatibilityAdmissionGate compatibility, TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    try
    {
        AgentLaunchApiRequest request = AgentApiCodec.DecodeLaunchRequest(
            await ReadAgentBody(http.Request, cancellationToken));
        IResult? denied = AuthorizeAgent(http, "agents:launch", request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId);
        if (denied is not null) return denied;
        CompatibilityDecision coreDecision = compatibility.Evaluate(CertaelProduct.Core,
            CertaelRelease.ProductVersion, CertaelRelease.ActionProtocolVersion);
        CertaelTelemetry.RecordCompatibility("core", CertaelRelease.ProductVersion,
            coreDecision.State.ToString(), coreDecision.PublicReason,
            coreDecision.ManifestRevision);
        if (!coreDecision.AllowsNewProtectedSession)
            return CompatibilityDenied(coreDecision);
        string minimumAgentVersion = request.MinimumAgentVersion;
        CompatibilityProductRule? agentRule = compatibility.Rule(CertaelProduct.Agent);
        if (agentRule is not null && SemanticVersion.Parse(minimumAgentVersion)
            < SemanticVersion.Parse(agentRule.MinimumSupportedVersion))
            minimumAgentVersion = agentRule.MinimumSupportedVersion;
        DateTimeOffset now = clock.GetUtcNow();
        var policy = new AgentPolicyClaims(1, request.PolicyId, request.TenantId, request.GameId,
            request.EnvironmentId, request.RequirementMode, request.HeartbeatSeconds,
            request.ReportSeconds, request.DisconnectGraceSeconds, minimumAgentVersion,
            now.AddSeconds(request.PolicyLifetimeSeconds));
        AgentLaunchBundle result = await lifecycle.LaunchAsync(new AgentLaunchParameters(
            request.TenantId, request.GameId, request.EnvironmentId, request.PlayerSubject,
            request.MatchId, request.AuthoritativeServerId, request.BuildId,
            request.AgentPublicKey, policy, TimeSpan.FromSeconds(request.SessionLifetimeSeconds)),
            cancellationToken);
        return Results.Bytes(AgentApiCodec.EncodeLaunchResponse(result), AgentApiCodec.ContentType);
    }
    catch (Exception exception) when (exception is AgentApiException or ArgumentException
        or FormatException or OverflowException or AgentPolicyLifecycleException
        or AgentBuildRegistryException)
    { return Results.BadRequest(); }
}).RequireAuthorization().RequireRateLimiting("service-operations");

app.MapPost("/v1/agent/sessions/{agentSessionId}/challenge", async (string agentSessionId,
    HttpContext http, AgentApiLifecycle lifecycle, CancellationToken cancellationToken) =>
{
    try
    {
        AgentOperationRequest request = AgentApiCodec.DecodeOperationRequest(
            await ReadAgentBody(http.Request, cancellationToken));
        IResult? denied = AuthorizeAgent(http, "agents:challenge", request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId);
        if (denied is not null) return denied;
        AgentReportChallenge? challenge = await lifecycle.ChallengeAsync(request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId, agentSessionId,
            cancellationToken);
        return challenge is null ? Results.NotFound()
            : Results.Bytes(AgentApiCodec.EncodeChallenge(challenge), AgentApiCodec.ContentType);
    }
    catch (AgentApiException) { return Results.BadRequest(); }
}).RequireAuthorization().RequireRateLimiting("service-operations");

app.MapPost("/v1/agent/sessions/{agentSessionId}/reports", async (string agentSessionId,
    HttpContext http, AgentApiLifecycle lifecycle, CancellationToken cancellationToken) =>
{
    try
    {
        AgentReportSubmission request = AgentApiCodec.DecodeReportSubmission(
            await ReadAgentBody(http.Request, cancellationToken));
        IResult? denied = AuthorizeAgent(http, "agents:report", request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId);
        if (denied is not null) return denied;
        if (!string.Equals(agentSessionId, request.Report.AgentSessionId, StringComparison.Ordinal))
            return Results.NotFound();
        AgentReportDecision decision = await lifecycle.SubmitAsync(request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId, request.Report,
            cancellationToken);
        return decision switch
        {
            AgentReportDecision.Accepted => Results.NoContent(),
            AgentReportDecision.BindingMismatch => Results.NotFound(),
            AgentReportDecision.Replay or AgentReportDecision.BrokenChain => Results.Conflict(),
            AgentReportDecision.Expired => Results.StatusCode(StatusCodes.Status410Gone),
            _ => Results.BadRequest()
        };
    }
    catch (Exception exception) when (exception is AgentApiException or AgentReportException
        or ArgumentException or OverflowException)
    { return Results.BadRequest(); }
}).RequireAuthorization().RequireRateLimiting("service-operations");

app.MapPost("/v1/agent/sessions/{agentSessionId}/health", async (string agentSessionId,
    HttpContext http, AgentApiLifecycle lifecycle, CancellationToken cancellationToken) =>
{
    try
    {
        AgentOperationRequest request = AgentApiCodec.DecodeOperationRequest(
            await ReadAgentBody(http.Request, cancellationToken));
        IResult? denied = AuthorizeAgent(http, "agents:health", request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId);
        if (denied is not null) return denied;
        AgentSessionHealth health = await lifecycle.HealthAsync(request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId, agentSessionId,
            TimeSpan.FromMinutes(2), cancellationToken);
        return Results.Bytes(AgentApiCodec.EncodeHealth(health), AgentApiCodec.ContentType);
    }
    catch (AgentApiException) { return Results.BadRequest(); }
}).RequireAuthorization().RequireRateLimiting("service-operations");

app.MapPost("/v1/agent/sessions/{agentSessionId}/revoke", async (string agentSessionId,
    HttpContext http, AgentApiLifecycle lifecycle, IAuditStore audit, TimeProvider clock,
    CancellationToken cancellationToken) =>
{
    try
    {
        AgentRevocationRequest request = AgentApiCodec.DecodeRevocationRequest(
            await ReadAgentBody(http.Request, cancellationToken));
        IResult? denied = AuthorizeAgent(http, "agents:revoke", request.TenantId,
            request.EnvironmentId, request.AuthoritativeServerId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        SignedAgentRevocation? revocation = await lifecycle.RevokeAndIssueAsync(
            request.TenantId, request.EnvironmentId,
            request.AuthoritativeServerId, agentSessionId, request.Reason, cancellationToken);
        bool revoked = revocation is not null;
        string subject = http.User.FindFirstValue("sub") ?? "unknown";
        DateTimeOffset now = clock.GetUtcNow();
        await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), request.TenantId,
            request.EnvironmentId, subject, "agent.session.revoke", "agent-session",
            agentSessionId, request.Reason, null, null, http.TraceIdentifier, now, revoked,
            http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
        return revocation is not null
            ? Results.Bytes(AgentGrantCodec.EncodeSignedRevocation(revocation),
                AgentApiCodec.ContentType)
            : Results.NotFound();
    }
    catch (AgentApiException) { return Results.BadRequest(); }
}).RequireAuthorization().RequireRateLimiting("service-operations");

app.MapPost("/v1/admin/agent-policies", async (AgentPolicyCreateRequest request,
    HttpContext http, IAgentPolicyAdministration policies, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-policies:create",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    DateTimeOffset now = DateTimeOffset.UtcNow;
    try
    {
        var claims = new AgentPolicyClaims(1, request.PolicyId, request.TenantId,
            request.GameId, request.EnvironmentId, request.RequirementMode,
            request.HeartbeatSeconds, request.ReportSeconds, request.DisconnectGraceSeconds,
            request.MinimumAgentVersion, request.ExpiresAt);
        AgentPolicyDeployment created = await policies.AddDraftAsync(claims, subject,
            cancellationToken);
        await AuditPolicy(audit, http, created, "agent-policy.create", request.Reason,
            null, PolicyStateDigest(created), true, cancellationToken);
        return Results.Created($"/v1/admin/agent-policies/{request.PolicyId}",
            AgentPolicyView.From(created));
    }
    catch (Exception exception) when (exception is AgentPolicyLifecycleException
        or ArgumentException or OverflowException)
    {
        await AuditPolicyFailure(audit, http, request.TenantId, request.EnvironmentId,
            request.PolicyId, "agent-policy.create", request.Reason, cancellationToken);
        return Results.BadRequest(new { error = "INVALID_AGENT_POLICY" });
    }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/privacy/delete-player", async (PlayerDeletionRequest request,
    HttpContext http, IAgentSessionStore agentSessions, IEvidenceStore evidence,
    IAuditStore audit, TimeProvider clock, CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "privacy:delete",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidIdentifier(request.PlayerSubject) || !ValidReason(request.Reason))
        return Results.BadRequest(new { error = "INVALID_DELETION_REQUEST" });
    AgentPlayerDeletionResult agent = await agentSessions.DeletePlayerAsync(
        request.TenantId, request.EnvironmentId, request.PlayerSubject, cancellationToken);
    await evidence.DeletePlayerAsync(request.TenantId, request.EnvironmentId,
        request.PlayerSubject,
        cancellationToken);
    DateTimeOffset now = clock.GetUtcNow();
    string operatorSubject = http.User.FindFirstValue("sub") ?? "unknown";
    string pseudonymousResource = Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes($"{request.TenantId}\0{request.PlayerSubject}")))
        .ToLowerInvariant();
    string afterDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{agent.SessionsDeleted}|{agent.RawReportsDeleted}|{now.ToUnixTimeSeconds()}")))
        .ToLowerInvariant();
    await audit.AppendAsync(new AuditEvent(Guid.NewGuid(), request.TenantId,
        request.EnvironmentId, operatorSubject, "privacy.player.delete", "player-subject",
        pseudonymousResource, request.Reason, null, afterDigest, http.TraceIdentifier, now,
        true, http.Connection.RemoteIpAddress?.ToString(), operatorSubject), cancellationToken);
    return Results.Ok(new
    {
        agentSessionsDeleted = agent.SessionsDeleted,
        rawAgentReportsDeleted = agent.RawReportsDeleted,
        derivedEvidenceDeleted = true
    });
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/agent-builds", async (AgentBuildMutationRequest request,
    HttpContext http, IAgentBuildAdministration builds, AgentGrantSigner signer,
    CompatibilityAdmissionGate compatibility, TimeProvider clock, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-builds:register",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    try
    {
        CompatibilityDecision sdkDecision = compatibility.Evaluate(CertaelProduct.Core,
            request.CoreSdkVersion, request.ActionProtocolVersion);
        CompatibilityDecision adapterDecision = compatibility.Evaluate(
            AdapterProduct(request.EngineAdapter), request.EngineAdapterVersion,
            request.AgentProtocolVersion);
        CertaelTelemetry.RecordCompatibility("core-sdk", request.CoreSdkVersion,
            sdkDecision.State.ToString(), sdkDecision.PublicReason,
            sdkDecision.ManifestRevision);
        CertaelTelemetry.RecordCompatibility(request.EngineAdapter,
            request.EngineAdapterVersion, adapterDecision.State.ToString(),
            adapterDecision.PublicReason, adapterDecision.ManifestRevision);
        if (!sdkDecision.AllowsNewProtectedSession) return CompatibilityDenied(sdkDecision);
        if (!adapterDecision.AllowsNewProtectedSession)
            return CompatibilityDenied(adapterDecision);
        DateTimeOffset now = clock.GetUtcNow();
        var claims = new AgentBuildManifestClaims(1, Guid.NewGuid().ToString("N"),
            request.TenantId, request.GameId, request.EnvironmentId, request.BuildId,
            (request.Files ?? []).Select(file => new ProtectedAgentBuildFile(file.Path, file.Size,
                file.Sha256)).ToArray(), now, request.ExpiresAt ?? now.AddDays(180),
            request.CoreSdkVersion, request.EngineAdapter, request.EngineAdapterVersion,
            request.CoreCAbiVersion, request.ActionProtocolVersion,
            request.AgentProtocolVersion, request.AgentProbeAbiVersion);
        byte[] signedManifest = AgentGrantCodec.EncodeSignedBuildManifest(
            signer.IssueBuildManifest(claims, now));
        ApprovedAgentBuild registered = await builds.RegisterAsync(request.TenantId,
            request.GameId, request.EnvironmentId, request.BuildId, subject, signedManifest,
            cancellationToken);
        await AuditAgentBuild(audit, http, request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, request.Reason, "agent-build.register", true,
            cancellationToken);
        return Results.Created("/v1/admin/agent-builds", registered);
    }
    catch (Exception exception) when (exception is AgentBuildRegistryException
        or ArgumentException or FormatException)
    {
        await AuditAgentBuild(audit, http, request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, request.Reason, "agent-build.register", false,
            cancellationToken);
        return exception is AgentBuildRegistryException ? Results.Conflict()
            : Results.BadRequest(new { error = "INVALID_AGENT_BUILD" });
    }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/agent-builds/revoke", async (AgentBuildRevocationRequest request,
    HttpContext http, IAgentBuildAdministration builds, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-builds:revoke",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    try
    {
        bool revoked = await builds.RevokeAsync(request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, subject, cancellationToken);
        await AuditAgentBuild(audit, http, request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, request.Reason, "agent-build.revoke", revoked,
            cancellationToken);
        return revoked ? Results.NoContent() : Results.NotFound();
    }
    catch (AgentBuildRegistryException)
    {
        await AuditAgentBuild(audit, http, request.TenantId, request.GameId,
            request.EnvironmentId, request.BuildId, request.Reason, "agent-build.revoke", false,
            cancellationToken);
        return Results.BadRequest();
    }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapGet("/v1/admin/agent-policies/{policyId}", async (string policyId,
    string tenantId, string environmentId, HttpContext http,
    IAgentPolicyAdministration policies, CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-policies:read", tenantId,
        environmentId);
    if (denied is not null) return denied;
    try
    {
        AgentPolicyDeployment result = await policies.GetAsync(tenantId, policyId,
            cancellationToken);
        return result.Claims.EnvironmentId == environmentId
            ? Results.Ok(AgentPolicyView.From(result)) : Results.NotFound();
    }
    catch (AgentPolicyLifecycleException) { return Results.NotFound(); }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/agent-policies/{policyId}/approve", async (string policyId,
    AgentPolicyMutationRequest request, HttpContext http,
    IAgentPolicyAdministration policies, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-policies:approve",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    try
    {
        AgentPolicyDeployment before = await policies.GetAsync(request.TenantId, policyId,
            cancellationToken);
        if (before.Claims.EnvironmentId != request.EnvironmentId) return Results.NotFound();
        AgentPolicyDeployment result = await policies.ApproveAsync(request.TenantId, policyId,
            subject, cancellationToken);
        await AuditPolicy(audit, http, result, "agent-policy.approve", request.Reason,
            PolicyStateDigest(before), PolicyStateDigest(result),
            true, cancellationToken);
        return Results.Ok(AgentPolicyView.From(result));
    }
    catch (AgentPolicyLifecycleException)
    {
        await AuditPolicyFailure(audit, http, request.TenantId, request.EnvironmentId,
            policyId, "agent-policy.approve", request.Reason, cancellationToken);
        return Results.NotFound();
    }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/agent-policies/{policyId}/promote", async (string policyId,
    AgentPolicyPromoteRequest request, HttpContext http,
    IAgentPolicyAdministration policies, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-policies:promote",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    try
    {
        AgentPolicyDeployment before = await policies.GetAsync(request.TenantId, policyId,
            cancellationToken);
        if (before.Claims.EnvironmentId != request.EnvironmentId) return Results.NotFound();
        AgentPolicyDeployment result = await policies.PromoteAsync(request.TenantId, policyId,
            request.Stage, request.CanaryPercentage, subject, cancellationToken);
        await AuditPolicy(audit, http, result, "agent-policy.promote", request.Reason,
            PolicyStateDigest(before), PolicyStateDigest(result),
            true, cancellationToken);
        return Results.Ok(AgentPolicyView.From(result));
    }
    catch (AgentPolicyLifecycleException)
    {
        await AuditPolicyFailure(audit, http, request.TenantId, request.EnvironmentId,
            policyId, "agent-policy.promote", request.Reason, cancellationToken);
        return Results.Conflict();
    }
}).RequireAuthorization().RequireRateLimiting("administration");

app.MapPost("/v1/admin/agent-policies/{policyId}/retire", async (string policyId,
    AgentPolicyMutationRequest request, HttpContext http,
    IAgentPolicyAdministration policies, IAuditStore audit,
    CancellationToken cancellationToken) =>
{
    IResult? denied = AuthorizeAdministration(http, "agent-policies:retire",
        request.TenantId, request.EnvironmentId);
    if (denied is not null) return denied;
    if (!ValidReason(request.Reason)) return Results.BadRequest();
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    try
    {
        AgentPolicyDeployment before = await policies.GetAsync(request.TenantId, policyId,
            cancellationToken);
        if (before.Claims.EnvironmentId != request.EnvironmentId) return Results.NotFound();
        AgentPolicyDeployment result = await policies.RetireAsync(request.TenantId, policyId,
            subject, cancellationToken);
        await AuditPolicy(audit, http, result, "agent-policy.retire", request.Reason,
            PolicyStateDigest(before), PolicyStateDigest(result),
            true, cancellationToken);
        return Results.Ok(AgentPolicyView.From(result));
    }
    catch (AgentPolicyLifecycleException)
    {
        await AuditPolicyFailure(audit, http, request.TenantId, request.EnvironmentId,
            policyId, "agent-policy.retire", request.Reason, cancellationToken);
        return Results.NotFound();
    }
}).RequireAuthorization().RequireRateLimiting("administration");

if (app.Services.GetService<ISignedConfigurationAdministration>() is not null)
{
    app.MapPost("/v1/admin/configurations/drafts", async (
        SignedConfigurationDraftRequest request, HttpContext http,
        ISignedConfigurationAdministration configurations, IAuditStore audit,
        CancellationToken cancellationToken) =>
    {
        IResult? denied = AuthorizeAdministration(http, "configurations:write",
            request.TenantId, request.EnvironmentId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        var artifact = new SignedConfigurationArtifact(request.Kind, request.TenantId,
            request.ArtifactId, request.Version, request.GameId, request.EnvironmentId,
            request.CanonicalDocument, request.Digest, request.Signature, request.SigningKeyId);
        try
        {
            SignedConfigurationDeployment result = await configurations.AddDraftAsync(artifact,
                http.User.FindFirstValue("sub") ?? "unknown", cancellationToken);
            await AuditConfiguration(audit, http, result, "configuration.create",
                request.Reason, null, Convert.ToHexString(result.Artifact.Digest), true,
                cancellationToken);
            return Results.Created($"/v1/admin/configurations/{request.Kind}/{request.ArtifactId}/{request.Version}",
                ConfigurationView.From(result));
        }
        catch (SignedConfigurationException)
        {
            await AuditConfigurationFailure(audit, http, request.TenantId,
                request.EnvironmentId, request.ArtifactId, "configuration.create",
                request.Reason, cancellationToken);
            return Results.BadRequest(new { error = "INVALID_SIGNED_CONFIGURATION" });
        }
    }).RequireAuthorization().RequireRateLimiting("administration");

    app.MapPost("/v1/admin/configurations/{kind}/{artifactId}/{version}/approve", async (
        SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationMutationRequest request, HttpContext http,
        ISignedConfigurationAdministration configurations, IAuditStore audit,
        CancellationToken cancellationToken) =>
    {
        IResult? denied = AuthorizeAdministration(http, "configurations:approve",
            request.TenantId, request.EnvironmentId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        try
        {
            SignedConfigurationDeployment before = await configurations.GetAsync(request.TenantId,
                kind, artifactId, version, cancellationToken);
            if (before.Artifact.EnvironmentId != request.EnvironmentId) return Results.NotFound();
            SignedConfigurationDeployment result = await configurations.ApproveAsync(request.TenantId,
                kind, artifactId, version, http.User.FindFirstValue("sub") ?? "unknown",
                cancellationToken);
            await AuditConfiguration(audit, http, result, "configuration.approve", request.Reason,
                ConfigurationStateDigest(before), ConfigurationStateDigest(result), true,
                cancellationToken);
            return Results.Ok(ConfigurationView.From(result));
        }
        catch (SignedConfigurationException) { return Results.NotFound(); }
    }).RequireAuthorization().RequireRateLimiting("administration");

    app.MapPost("/v1/admin/configurations/{kind}/{artifactId}/{version}/promote", async (
        SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationPromoteRequest request, HttpContext http,
        ISignedConfigurationAdministration configurations, IAuditStore audit,
        CancellationToken cancellationToken) =>
    {
        IResult? denied = AuthorizeAdministration(http, "configurations:promote",
            request.TenantId, request.EnvironmentId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        try
        {
            SignedConfigurationDeployment before = await configurations.GetAsync(request.TenantId,
                kind, artifactId, version, cancellationToken);
            if (before.Artifact.EnvironmentId != request.EnvironmentId) return Results.NotFound();
            SignedConfigurationDeployment result = await configurations.PromoteAsync(request.TenantId,
                kind, artifactId, version, request.Stage, request.CanaryPercentage,
                http.User.FindFirstValue("sub") ?? "unknown", cancellationToken);
            await AuditConfiguration(audit, http, result, "configuration.promote", request.Reason,
                ConfigurationStateDigest(before), ConfigurationStateDigest(result), true,
                cancellationToken);
            return Results.Ok(ConfigurationView.From(result));
        }
        catch (SignedConfigurationException) { return Results.Conflict(); }
    }).RequireAuthorization().RequireRateLimiting("administration");

    app.MapPost("/v1/admin/configurations/{kind}/rollback", async (
        SignedConfigurationKind kind, SignedConfigurationRollbackRequest request,
        HttpContext http, ISignedConfigurationAdministration configurations, IAuditStore audit,
        CancellationToken cancellationToken) =>
    {
        IResult? denied = AuthorizeAdministration(http, "configurations:rollback",
            request.TenantId, request.EnvironmentId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        try
        {
            SignedConfigurationDeployment result = await configurations.RollbackAsync(
                request.TenantId, kind, request.GameId, request.EnvironmentId,
                http.User.FindFirstValue("sub") ?? "unknown", cancellationToken);
            await AuditConfiguration(audit, http, result, "configuration.rollback", request.Reason,
                null, ConfigurationStateDigest(result), true, cancellationToken);
            return Results.Ok(ConfigurationView.From(result));
        }
        catch (SignedConfigurationException) { return Results.Conflict(); }
    }).RequireAuthorization().RequireRateLimiting("administration");

    app.MapPost("/v1/admin/configurations/{kind}/{artifactId}/{version}/retire", async (
        SignedConfigurationKind kind, string artifactId, string version,
        SignedConfigurationMutationRequest request, HttpContext http,
        ISignedConfigurationAdministration configurations, IAuditStore audit,
        CancellationToken cancellationToken) =>
    {
        IResult? denied = AuthorizeAdministration(http, "configurations:retire",
            request.TenantId, request.EnvironmentId);
        if (denied is not null) return denied;
        if (!ValidReason(request.Reason)) return Results.BadRequest();
        try
        {
            SignedConfigurationDeployment before = await configurations.GetAsync(request.TenantId,
                kind, artifactId, version, cancellationToken);
            if (before.Artifact.EnvironmentId != request.EnvironmentId) return Results.NotFound();
            SignedConfigurationDeployment result = await configurations.RetireAsync(request.TenantId,
                kind, artifactId, version, http.User.FindFirstValue("sub") ?? "unknown",
                cancellationToken);
            await AuditConfiguration(audit, http, result, "configuration.retire", request.Reason,
                ConfigurationStateDigest(before), ConfigurationStateDigest(result), true,
                cancellationToken);
            return Results.Ok(ConfigurationView.From(result));
        }
        catch (SignedConfigurationException) { return Results.NotFound(); }
    }).RequireAuthorization().RequireRateLimiting("administration");
}

if (app.Services.GetService<NpgsqlDataSource>() is { } dataSource)
{
    await new PostgresMigrationRunner(dataSource).ApplyAsync();
    await SeedConfiguredAgentPoliciesAsync(app.Services, builder.Configuration,
        builder.Environment, app.Lifetime.ApplicationStopping);
    await SeedConfiguredAgentBuildsAsync(app.Services, builder.Configuration,
        builder.Environment, app.Lifetime.ApplicationStopping);
}

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

static AgentGrantSigner LoadAgentGrantSigner(IConfiguration configuration,
    IHostEnvironment environment)
{
    string keyId = RequiredSetting(configuration, environment,
        "Agent:SigningKeyId", "development-agent-key");
    string? path = configuration["Agent:SigningPrivateKeyPath"];
    if (string.IsNullOrWhiteSpace(path))
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                "Agent:SigningPrivateKeyPath is required outside Development.");
        return new AgentGrantSigner(Key.Create(SignatureAlgorithm.Ed25519), keyId);
    }
    byte[] material = File.ReadAllBytes(path);
    try
    {
        return new AgentGrantSigner(Key.Import(SignatureAlgorithm.Ed25519, material,
            KeyBlobFormat.RawPrivateKey), keyId);
    }
    finally { CryptographicOperations.ZeroMemory(material); }
}

static ISignedConfigurationVerifier LoadSignedConfigurationVerifier(
    IConfiguration configuration, IHostEnvironment environment)
{
    IConfigurationSection[] configured = configuration
        .GetSection("ConfigurationSigning:TrustedKeys").GetChildren().ToArray();
    if (configured.Length == 0 && !environment.IsDevelopment())
        throw new InvalidOperationException(
            "At least one ConfigurationSigning:TrustedKeys entry is required outside Development.");
    var keys = new Dictionary<string, ECDsa>(StringComparer.Ordinal);
    try
    {
        foreach (IConfigurationSection item in configured)
        {
            string keyId = item["KeyId"]
                ?? throw new InvalidOperationException("Configuration trust key requires KeyId.");
            string path = item["PublicKeyPemPath"]
                ?? throw new InvalidOperationException($"Configuration trust key {keyId} requires PublicKeyPemPath.");
            if (!ValidIdentifier(keyId) || keys.ContainsKey(keyId))
                throw new InvalidOperationException("Configuration trust key ID is invalid or duplicated.");
            var key = ECDsa.Create();
            try { key.ImportFromPem(File.ReadAllText(path)); }
            catch { key.Dispose(); throw; }
            keys.Add(keyId, key);
        }
        return new SignedConfigurationVerifier(new RulePackVerifier(keys),
            new ProtectionProfileVerifier(keys));
    }
    catch
    {
        foreach (ECDsa key in keys.Values) key.Dispose();
        throw;
    }
}

static AgentPolicyLifecycleStore LoadAgentPolicyLifecycle(IConfiguration configuration,
    IHostEnvironment environment, AgentGrantSigner signer, TimeProvider clock)
{
    var store = new AgentPolicyLifecycleStore(signer, clock);
    IConfigurationSection[] configured = configuration.GetSection("Agent:Policies")
        .GetChildren().ToArray();
    if (configured.Length == 0)
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                "At least one immutable Agent:Policies entry is required outside Development.");
        DateTimeOffset now = clock.GetUtcNow();
        var development = new AgentPolicyClaims(1, "development-default", "development-tenant",
            "development-game",
            "development", AgentRequirementMode.Optional, 15, 60, 30, "0.1.0",
            now.AddHours(12));
        store.AddDraft(development, "development-bootstrap");
        store.Approve(development.TenantId, development.PolicyId, "development-reviewer-a");
        store.Approve(development.TenantId, development.PolicyId, "development-reviewer-b");
        store.Promote(development.TenantId, development.PolicyId,
            AgentPolicyDeploymentStage.Enforced, 0,
            "development-bootstrap");
        return store;
    }

    foreach (IConfigurationSection item in configured)
    {
        AgentPolicyConfiguration value = ReadAgentPolicyConfiguration(item);
        AgentPolicyClaims claims = value.Claims;
        store.AddDraft(claims, item["AuthorSubject"] ?? "deployment-config");
        foreach (string approval in value.Approvals)
            store.Approve(claims.TenantId, claims.PolicyId, approval);
        store.Promote(claims.TenantId, claims.PolicyId, value.Stage, value.CanaryPercentage,
            item["OperatorSubject"] ?? "deployment-config");
    }
    return store;
}

static async Task SeedConfiguredAgentPoliciesAsync(IServiceProvider services,
    IConfiguration configuration, IHostEnvironment environment,
    CancellationToken cancellationToken)
{
    IConfigurationSection[] configured = configuration.GetSection("Agent:Policies")
        .GetChildren().ToArray();
    if (configured.Length == 0)
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                "At least one immutable Agent:Policies entry is required outside Development.");
        return;
    }
    IAgentPolicyAdministration policies =
        services.GetRequiredService<IAgentPolicyAdministration>();
    foreach (IConfigurationSection item in configured)
    {
        AgentPolicyConfiguration value = ReadAgentPolicyConfiguration(item);
        AgentPolicyDeployment? existing = null;
        try
        {
            existing = await policies.GetAsync(value.Claims.TenantId, value.Claims.PolicyId,
                cancellationToken);
        }
        catch (AgentPolicyLifecycleException) { }
        if (existing is null)
        {
            await policies.AddDraftAsync(value.Claims,
                item["AuthorSubject"] ?? "deployment-config", cancellationToken);
            foreach (string approval in value.Approvals)
                await policies.ApproveAsync(value.Claims.TenantId, value.Claims.PolicyId,
                    approval, cancellationToken);
            await policies.PromoteAsync(value.Claims.TenantId, value.Claims.PolicyId,
                value.Stage, value.CanaryPercentage,
                item["OperatorSubject"] ?? "deployment-config", cancellationToken);
            continue;
        }
        if (existing.Claims != value.Claims || existing.Stage != value.Stage
            || existing.CanaryPercentage != value.CanaryPercentage)
            throw new InvalidOperationException(
                $"Stored Agent policy {value.Claims.PolicyId} differs from immutable configuration.");
    }
}

static AgentPolicyConfiguration ReadAgentPolicyConfiguration(IConfigurationSection item)
{
    string policyId = item["PolicyId"]
        ?? throw new InvalidOperationException("Agent policy requires PolicyId.");
    string gameId = item["GameId"]
        ?? throw new InvalidOperationException($"Agent policy {policyId} requires GameId.");
    string tenantId = item["TenantId"]
        ?? throw new InvalidOperationException($"Agent policy {policyId} requires TenantId.");
    string environmentId = item["EnvironmentId"]
        ?? throw new InvalidOperationException($"Agent policy {policyId} requires EnvironmentId.");
    if (!Enum.TryParse(item["RequirementMode"], true, out AgentRequirementMode mode)
        || !Enum.IsDefined(mode))
        throw new InvalidOperationException($"Agent policy {policyId} has invalid RequirementMode.");
    if (!DateTimeOffset.TryParse(item["ExpiresAt"], out DateTimeOffset expiresAt))
        throw new InvalidOperationException($"Agent policy {policyId} requires ExpiresAt.");
    if (!Enum.TryParse(item["Stage"], true, out AgentPolicyDeploymentStage stage)
        || stage is AgentPolicyDeploymentStage.Draft or AgentPolicyDeploymentStage.Retired)
        throw new InvalidOperationException($"Agent policy {policyId} has invalid active Stage.");
    var claims = new AgentPolicyClaims(1, policyId, tenantId, gameId, environmentId, mode,
        item.GetValue<uint>("HeartbeatSeconds", 15),
        item.GetValue<uint>("ReportSeconds", 60),
        item.GetValue<uint>("DisconnectGraceSeconds", 30),
        item["MinimumAgentVersion"] ?? "0.1.0", expiresAt);
    string[] approvals = (item.GetSection("ApprovalSubjects").Get<string[]>() ?? [])
        .Distinct(StringComparer.Ordinal).ToArray();
    return new(claims, stage, item.GetValue<int>("CanaryPercentage", 0), approvals);
}

static InMemoryAgentBuildRegistry LoadAgentBuildRegistry(IConfiguration configuration,
    IHostEnvironment environment, TimeProvider timeProvider)
{
    var registry = new InMemoryAgentBuildRegistry(timeProvider);
    IConfigurationSection[] configured = configuration.GetSection("Agent:ApprovedBuilds")
        .GetChildren().ToArray();
    if (configured.Length == 0 && environment.IsDevelopment())
        return registry;
    foreach (IConfigurationSection item in configured)
    {
        AgentBuildConfiguration build = ReadAgentBuildConfiguration(item);
        registry.RegisterAsync(build.TenantId, build.GameId, build.EnvironmentId,
            build.BuildId, "deployment-config", build.SignedBuildManifest,
            CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();
    }
    return registry;
}

static async Task SeedConfiguredAgentBuildsAsync(IServiceProvider services,
    IConfiguration configuration, IHostEnvironment environment,
    CancellationToken cancellationToken)
{
    IConfigurationSection[] configured = configuration.GetSection("Agent:ApprovedBuilds")
        .GetChildren().ToArray();
    if (configured.Length == 0)
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                "At least one Agent:ApprovedBuilds entry is required outside Development.");
        return;
    }
    IAgentBuildRegistry registry = services.GetRequiredService<IAgentBuildRegistry>();
    IAgentBuildAdministration administration =
        services.GetRequiredService<IAgentBuildAdministration>();
    foreach (IConfigurationSection item in configured)
    {
        AgentBuildConfiguration build = ReadAgentBuildConfiguration(item);
        if (!await registry.IsApprovedAsync(build.TenantId, build.GameId,
            build.EnvironmentId, build.BuildId, cancellationToken))
            await administration.RegisterAsync(build.TenantId, build.GameId,
                build.EnvironmentId, build.BuildId, "deployment-config",
                build.SignedBuildManifest, cancellationToken);
    }
}

static AgentBuildConfiguration ReadAgentBuildConfiguration(IConfigurationSection item) => new(
    item["TenantId"] ?? throw new InvalidOperationException("Approved build requires TenantId."),
    item["GameId"] ?? throw new InvalidOperationException("Approved build requires GameId."),
    item["EnvironmentId"] ?? throw new InvalidOperationException(
        "Approved build requires EnvironmentId."),
    item["BuildId"] ?? throw new InvalidOperationException("Approved build requires BuildId."),
    Convert.FromBase64String(item["SignedBuildManifestBase64"]
        ?? throw new InvalidOperationException(
            "Approved build requires SignedBuildManifestBase64.")));

static string RequiredSetting(IConfiguration configuration, IHostEnvironment environment,
    string key, string developmentDefault) =>
    !string.IsNullOrWhiteSpace(configuration[key]) ? configuration[key]!
    : environment.IsDevelopment() ? developmentDefault
    : throw new InvalidOperationException($"{key} is required outside Development.");

static CompatibilityAdmissionGate LoadCompatibilityGate(IConfiguration configuration,
    IHostEnvironment environment, TimeProvider clock)
{
    string? manifestPath = configuration["Compatibility:SignedManifestPath"];
    string? trustStorePath = configuration["Compatibility:TrustStorePath"];
    IConfigurationSection[] configuredKeys = configuration
        .GetSection("Compatibility:TrustedKeys").GetChildren().ToArray();
    if (string.IsNullOrWhiteSpace(manifestPath)
        || (string.IsNullOrWhiteSpace(trustStorePath) && configuredKeys.Length == 0))
    {
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                "A signed Compatibility manifest and offline TrustedKeys are required outside Development.");
        DateTimeOffset now = clock.GetUtcNow();
        var development = new CompatibilityManifestClaims(1, 1, now.AddMinutes(-1),
            now.AddHours(12),
            Enum.GetValues<CertaelProduct>().Select(product =>
                new CompatibilityProductRule(product, "0.2.0", CertaelRelease.ProductVersion,
                    1, 1)).ToArray(), []);
        return new CompatibilityAdmissionGate(development, clock);
    }
    IEnumerable<CompatibilityVerificationKey> loadedKeys;
    if (!string.IsNullOrWhiteSpace(trustStorePath))
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(trustStorePath));
        loadedKeys = document.RootElement.GetProperty("keys").EnumerateArray().Select(item =>
            new CompatibilityVerificationKey(
                item.GetProperty("key_id").GetString()
                    ?? throw new InvalidOperationException("Compatibility key ID is missing."),
                Convert.FromHexString(item.GetProperty("public_key_hex").GetString()
                    ?? throw new InvalidOperationException("Compatibility public key is missing.")),
                DateTimeOffset.FromUnixTimeSeconds(
                    item.GetProperty("not_before_unix").GetInt64()),
                DateTimeOffset.FromUnixTimeSeconds(
                    item.GetProperty("not_after_unix").GetInt64()),
                item.GetProperty("revoked").GetBoolean())).ToArray();
    }
    else
    {
        loadedKeys = configuredKeys.Select(item =>
        {
            string keyId = item["KeyId"]
                ?? throw new InvalidOperationException("Compatibility trust key requires KeyId.");
            string publicKeyPath = item["PublicKeyPath"]
                ?? throw new InvalidOperationException(
                    $"Compatibility trust key {keyId} requires PublicKeyPath.");
            if (!DateTimeOffset.TryParse(item["NotBefore"], out DateTimeOffset notBefore)
                || !DateTimeOffset.TryParse(item["NotAfter"], out DateTimeOffset notAfter))
                throw new InvalidOperationException(
                    $"Compatibility trust key {keyId} has invalid validity bounds.");
            return new CompatibilityVerificationKey(keyId, File.ReadAllBytes(publicKeyPath),
                notBefore, notAfter, item.GetValue("Revoked", false));
        }).ToArray();
    }
    var keys = new CompatibilityVerificationKeyRing(loadedKeys);
    byte[] envelope = File.ReadAllBytes(manifestPath);
    CompatibilityManifestClaims claims = CompatibilityManifestSigner.Verify(
        CompatibilityManifestCodec.DecodeSigned(envelope), keys, clock.GetUtcNow());
    ulong minimumRevision = configuration.GetValue<ulong>("Compatibility:MinimumRevision", 1);
    if (claims.Revision < minimumRevision)
        throw new InvalidOperationException(
            "Signed compatibility manifest is below Compatibility:MinimumRevision.");
    return new CompatibilityAdmissionGate(claims, clock);
}

static IResult CompatibilityDenied(CompatibilityDecision decision) => decision.State switch
{
    CompatibilityState.UpdateRequired => Results.Json(new
    {
        error = decision.PublicReason,
        recommendedVersion = decision.RecommendedVersion,
        manifestRevision = decision.ManifestRevision
    }, statusCode: StatusCodes.Status426UpgradeRequired),
    CompatibilityState.Revoked => Results.Json(new
    {
        error = decision.PublicReason,
        recommendedVersion = decision.RecommendedVersion,
        manifestRevision = decision.ManifestRevision
    }, statusCode: StatusCodes.Status403Forbidden),
    _ => Results.Json(new
    {
        error = decision.PublicReason,
        recommendedVersion = decision.RecommendedVersion,
        manifestRevision = decision.ManifestRevision
    }, statusCode: StatusCodes.Status503ServiceUnavailable)
};

static CertaelProduct AdapterProduct(string value) => value.ToLowerInvariant() switch
{
    "godot" => CertaelProduct.GodotAdapter,
    "unity" => CertaelProduct.UnityAdapter,
    "unreal" => CertaelProduct.UnrealAdapter,
    "native" => CertaelProduct.NativeServerSdk,
    _ => throw new ArgumentException("Engine adapter is unsupported.")
};

static bool ValidReason(string value) => !string.IsNullOrWhiteSpace(value)
    && value.Length <= 512 && !value.Any(char.IsControl);

static bool ValidIdentifier(string value) => !string.IsNullOrWhiteSpace(value)
    && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character)
        || character is '.' or '_' or '-');

static void ConfigurePersistence(WebApplicationBuilder builder)
{
    string? postgres = builder.Configuration.GetConnectionString("Postgres");
    string? redis = builder.Configuration.GetConnectionString("Redis");
    if (!string.IsNullOrWhiteSpace(postgres) && !string.IsNullOrWhiteSpace(redis))
    {
        builder.Services.AddSingleton(NpgsqlDataSource.Create(postgres));
        builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redis));
        builder.Services.AddSingleton<ITicketRedemptionStore, PostgresTicketRedemptionStore>();
        builder.Services.AddSingleton<PostgresSessionStore>();
        builder.Services.AddSingleton<ISessionAuthorizationStore>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<ISessionAuthorizationWriter>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<ISessionAdministrationStore>(service => service.GetRequiredService<PostgresSessionStore>());
        builder.Services.AddSingleton<IAuditStore, PostgresAuditStore>();
        builder.Services.AddSingleton<IEvidenceStore>(service => new PostgresEvidenceStore(
            service.GetRequiredService<NpgsqlDataSource>(), TimeSpan.FromDays(
                builder.Configuration.GetValue("Privacy:DerivedEvidenceRetentionDays", 30))));
        builder.Services.AddSingleton<IAgentSessionStore>(service =>
            new PostgresAgentSessionStore(service.GetRequiredService<NpgsqlDataSource>(),
                TimeSpan.FromMinutes(builder.Configuration.GetValue(
                    "Privacy:RawAgentReportRetentionMinutes", 1440))));
        builder.Services.AddSingleton<PostgresAgentPolicyStore>();
        builder.Services.AddSingleton<IAgentPolicyResolver>(service =>
            service.GetRequiredService<PostgresAgentPolicyStore>());
        builder.Services.AddSingleton<IAgentPolicyAdministration>(service =>
            service.GetRequiredService<PostgresAgentPolicyStore>());
        builder.Services.AddSingleton<PostgresAgentBuildRegistry>();
        builder.Services.AddSingleton<IAgentBuildRegistry>(service =>
            service.GetRequiredService<PostgresAgentBuildRegistry>());
        builder.Services.AddSingleton<IAgentBuildAdministration>(service =>
            service.GetRequiredService<PostgresAgentBuildRegistry>());
        builder.Services.AddSingleton<PostgresSignedConfigurationStore>();
        builder.Services.AddSingleton<ISignedConfigurationAdministration>(service =>
            service.GetRequiredService<PostgresSignedConfigurationStore>());
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
    builder.Services.AddSingleton<IEvidenceStore, InMemoryEvidenceStore>();
    builder.Services.AddSingleton<IAgentSessionStore, InMemoryAgentSessionStore>();
    builder.Services.AddSingleton(service => LoadAgentPolicyLifecycle(builder.Configuration,
        builder.Environment, service.GetRequiredService<AgentGrantSigner>(),
        service.GetRequiredService<TimeProvider>()));
    builder.Services.AddSingleton<IAgentPolicyResolver>(service =>
        service.GetRequiredService<AgentPolicyLifecycleStore>());
    builder.Services.AddSingleton<IAgentPolicyAdministration>(service =>
        service.GetRequiredService<AgentPolicyLifecycleStore>());
    builder.Services.AddSingleton(service => LoadAgentBuildRegistry(builder.Configuration,
        builder.Environment, service.GetRequiredService<TimeProvider>()));
    builder.Services.AddSingleton<IAgentBuildRegistry>(service =>
        service.GetRequiredService<InMemoryAgentBuildRegistry>());
    builder.Services.AddSingleton<IAgentBuildAdministration>(service =>
        service.GetRequiredService<InMemoryAgentBuildRegistry>());
}

static async ValueTask<byte[]> ReadAgentBody(HttpRequest request,
    CancellationToken cancellationToken)
{
    if (request.ContentType is null || !request.ContentType.StartsWith(
        AgentApiCodec.ContentType, StringComparison.OrdinalIgnoreCase)
        || request.ContentLength > AgentApiCodec.MaximumBody)
        throw new AgentApiException("Agent API content type or size is invalid.");
    using var stream = new MemoryStream();
    await request.Body.CopyToAsync(stream, cancellationToken);
    if (stream.Length is < 1 or > AgentApiCodec.MaximumBody)
        throw new AgentApiException("Agent API body is invalid.");
    return stream.ToArray();
}

static IResult? AuthorizeAgent(HttpContext http, string scope, string tenantId,
    string environmentId, string authoritativeServerId)
{
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(http.User,
        http.Connection.ClientCertificate, scope, tenantId, environmentId);
    if (identity == ServiceIdentityDecision.Unauthenticated) return Results.Unauthorized();
    if (identity == ServiceIdentityDecision.Forbidden) return Results.Forbid();
    return string.Equals(http.User.FindFirstValue("server_id"), authoritativeServerId,
        StringComparison.Ordinal) ? null : Results.Forbid();
}

static IResult? AuthorizeAdministration(HttpContext http, string scope, string tenantId,
    string environmentId)
{
    ServiceIdentityDecision identity = ServiceIdentityGuard.Authorize(http.User,
        http.Connection.ClientCertificate, scope, tenantId, environmentId);
    return identity switch
    {
        ServiceIdentityDecision.Unauthenticated => Results.Unauthorized(),
        ServiceIdentityDecision.Forbidden => Results.Forbid(),
        _ => null
    };
}

static ValueTask AuditPolicy(IAuditStore audit, HttpContext http,
    AgentPolicyDeployment deployment, string operation, string reason,
    string? beforeDigest, string? afterDigest, bool succeeded,
    CancellationToken cancellationToken)
{
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    return audit.AppendAsync(new AuditEvent(Guid.NewGuid(), deployment.Claims.TenantId,
        deployment.Claims.EnvironmentId, subject, operation, "agent-policy",
        deployment.Claims.PolicyId, reason, beforeDigest, afterDigest,
        http.TraceIdentifier, DateTimeOffset.UtcNow, succeeded,
        http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
}

static ValueTask AuditPolicyFailure(IAuditStore audit, HttpContext http, string tenantId,
    string environmentId, string policyId, string operation, string reason,
    CancellationToken cancellationToken)
{
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    return audit.AppendAsync(new AuditEvent(Guid.NewGuid(), SafeAuditText(tenantId),
        SafeAuditText(environmentId), subject, operation, "agent-policy",
        SafeAuditText(policyId), SafeAuditText(reason, 512), null, null,
        http.TraceIdentifier, DateTimeOffset.UtcNow, false,
        http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
}

static string PolicyStateDigest(AgentPolicyDeployment value)
{
    string approvals = string.Join(',', value.Approvals.Select(approval =>
        approval.ApproverSubject).Order(StringComparer.Ordinal));
    byte[] state = Encoding.UTF8.GetBytes(string.Join('|',
        Convert.ToHexString(value.PolicyDigest), (int)value.Stage,
        value.CanaryPercentage, approvals));
    return Convert.ToHexString(SHA256.HashData(state));
}

static string SafeAuditText(string value, int maximum = 128) =>
    !string.IsNullOrWhiteSpace(value) && value.Length <= maximum
        && !value.Any(char.IsControl) ? value : "invalid";

static ValueTask AuditAgentBuild(IAuditStore audit, HttpContext http,
    string tenantId, string gameId, string environmentId, string buildId, string reason,
    string operation, bool succeeded,
    CancellationToken cancellationToken)
{
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    string resource = string.Join('/', SafeAuditText(gameId), SafeAuditText(buildId));
    string? afterDigest = succeeded ? Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(string.Join('|', SafeAuditText(tenantId),
            SafeAuditText(environmentId), SafeAuditText(gameId),
            SafeAuditText(buildId), operation)))).ToLowerInvariant() : null;
    return audit.AppendAsync(new AuditEvent(Guid.NewGuid(), SafeAuditText(tenantId),
        SafeAuditText(environmentId), subject, operation, "agent-build", resource,
        reason, null, afterDigest, http.TraceIdentifier,
        DateTimeOffset.UtcNow, succeeded, http.Connection.RemoteIpAddress?.ToString(), subject),
        cancellationToken);
}

static ValueTask AuditConfiguration(IAuditStore audit, HttpContext http,
    SignedConfigurationDeployment deployment, string operation, string reason,
    string? beforeDigest, string? afterDigest, bool succeeded,
    CancellationToken cancellationToken)
{
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    return audit.AppendAsync(new AuditEvent(Guid.NewGuid(), deployment.Artifact.TenantId,
        deployment.Artifact.EnvironmentId, subject, operation, "signed-configuration",
        $"{deployment.Artifact.Kind}/{deployment.Artifact.ArtifactId}/{deployment.Artifact.Version}",
        reason, beforeDigest, afterDigest, http.TraceIdentifier, DateTimeOffset.UtcNow,
        succeeded, http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
}

static ValueTask AuditConfigurationFailure(IAuditStore audit, HttpContext http,
    string tenantId, string environmentId, string artifactId, string operation,
    string reason, CancellationToken cancellationToken)
{
    string subject = http.User.FindFirstValue("sub") ?? "unknown";
    return audit.AppendAsync(new AuditEvent(Guid.NewGuid(), SafeAuditText(tenantId),
        SafeAuditText(environmentId), subject, operation, "signed-configuration",
        SafeAuditText(artifactId), SafeAuditText(reason, 512), null, null,
        http.TraceIdentifier, DateTimeOffset.UtcNow, false,
        http.Connection.RemoteIpAddress?.ToString(), subject), cancellationToken);
}

static string ConfigurationStateDigest(SignedConfigurationDeployment value)
{
    string approvals = string.Join(',', value.Approvals.Select(approval =>
        approval.ApproverSubject).Order(StringComparer.Ordinal));
    return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|',
        Convert.ToHexString(value.Artifact.Digest), (int)value.Stage,
        value.CanaryPercentage, approvals))));
}

public sealed record IssueTicketRequest(
    string TenantId, string GameId, string EnvironmentId, string PlayerSubject,
    string MatchId, string ServerId, string BuildId, string ProtectionProfile,
    byte[] EphemeralPublicKey);

public sealed record PlayerDeletionRequest(
    string TenantId, string EnvironmentId, string PlayerSubject, string Reason);

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

public sealed record AgentPolicyCreateRequest(
    string TenantId, string PolicyId, string GameId, string EnvironmentId,
    AgentRequirementMode RequirementMode, uint HeartbeatSeconds, uint ReportSeconds,
    uint DisconnectGraceSeconds, string MinimumAgentVersion, DateTimeOffset ExpiresAt,
    string Reason);

public sealed record AgentBuildMutationRequest(
    string TenantId, string GameId, string EnvironmentId, string BuildId, string Reason,
    string CoreSdkVersion, string EngineAdapter, string EngineAdapterVersion,
    uint CoreCAbiVersion, uint ActionProtocolVersion, uint AgentProtocolVersion,
    uint AgentProbeAbiVersion, IReadOnlyList<AgentBuildFileRequest>? Files = null,
    DateTimeOffset? ExpiresAt = null);

public sealed record AgentBuildRevocationRequest(string TenantId, string GameId,
    string EnvironmentId, string BuildId, string Reason);

public sealed record AgentBuildFileRequest(string Path, ulong Size, byte[] Sha256);

public sealed record CompatibilityCheckRequest(string TenantId, string EnvironmentId,
    string Product, string Version, uint ProtocolVersion);

public sealed record AgentPolicyMutationRequest(
    string TenantId, string EnvironmentId, string Reason);

public sealed record AgentPolicyPromoteRequest(
    string TenantId, string EnvironmentId, AgentPolicyDeploymentStage Stage,
    int CanaryPercentage, string Reason);

public sealed record SignedConfigurationDraftRequest(
    SignedConfigurationKind Kind, string TenantId, string ArtifactId, string Version,
    string GameId, string EnvironmentId, byte[] CanonicalDocument, byte[] Digest,
    byte[] Signature, string SigningKeyId, string Reason);

public sealed record SignedConfigurationMutationRequest(
    string TenantId, string EnvironmentId, string Reason);

public sealed record SignedConfigurationPromoteRequest(
    string TenantId, string EnvironmentId, SignedConfigurationStage Stage,
    int CanaryPercentage, string Reason);

public sealed record SignedConfigurationRollbackRequest(
    string TenantId, string GameId, string EnvironmentId, string Reason);

public sealed record ConfigurationView(
    SignedConfigurationKind Kind, string TenantId, string ArtifactId, string Version,
    string GameId, string EnvironmentId, SignedConfigurationStage Stage,
    int CanaryPercentage, int ApprovalCount, string Digest,
    DateTimeOffset UpdatedAt, string UpdatedBy)
{
    public static ConfigurationView From(SignedConfigurationDeployment value) => new(
        value.Artifact.Kind, value.Artifact.TenantId, value.Artifact.ArtifactId,
        value.Artifact.Version, value.Artifact.GameId, value.Artifact.EnvironmentId,
        value.Stage, value.CanaryPercentage, value.Approvals.Count,
        Convert.ToHexString(value.Artifact.Digest), value.UpdatedAt, value.UpdatedBy);
}

public sealed record AgentPolicyView(
    string TenantId, string PolicyId, string GameId, string EnvironmentId,
    AgentRequirementMode RequirementMode, DateTimeOffset ExpiresAt,
    AgentPolicyDeploymentStage Stage, int CanaryPercentage, int ApprovalCount,
    string Digest, DateTimeOffset UpdatedAt, string UpdatedBy)
{
    public static AgentPolicyView From(AgentPolicyDeployment value) => new(
        value.Claims.TenantId, value.Claims.PolicyId, value.Claims.GameId,
        value.Claims.EnvironmentId, value.Claims.RequirementMode, value.Claims.ExpiresAt,
        value.Stage, value.CanaryPercentage, value.Approvals.Count,
        Convert.ToHexString(value.PolicyDigest), value.UpdatedAt, value.UpdatedBy);
}

file sealed record AgentPolicyConfiguration(
    AgentPolicyClaims Claims, AgentPolicyDeploymentStage Stage,
    int CanaryPercentage, IReadOnlyList<string> Approvals);

file sealed record AgentBuildConfiguration(
    string TenantId, string GameId, string EnvironmentId, string BuildId,
    byte[] SignedBuildManifest);

file static class CertaelRelease
{
    public const string ProductVersion = "0.3.0-alpha.1";
    public const uint ActionProtocolVersion = 1;
}

public partial class Program;

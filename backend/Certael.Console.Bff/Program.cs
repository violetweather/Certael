using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Antiforgery;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
LoadExternalConfiguration(builder);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddAntiforgery(options => options.HeaderName = "X-Certael-CSRF");
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
}).AddCookie(options =>
{
    options.Cookie.Name = "__Host-certael-console";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.SlidingExpiration = false;
}).AddOpenIdConnect(options =>
{
    options.Authority = Required(builder.Configuration, "Authentication:Authority");
    options.ClientId = Required(builder.Configuration, "Authentication:ClientId");
    options.ClientSecret = Required(builder.Configuration, "Authentication:ClientSecret");
    options.ResponseType = "code";
    options.UsePkce = true;
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Clear();
    foreach (string scope in (builder.Configuration.GetSection("Authentication:Scopes")
        .Get<string[]>() ?? ["openid", "profile", "offline_access"]))
        options.Scope.Add(scope);
});
builder.Services.AddAuthorization();

X509Certificate2 clientCertificate = LoadClientCertificate(builder.Configuration);
builder.Services.AddSingleton(clientCertificate);
builder.Services.AddHttpClient("token-exchange").ConfigurePrimaryHttpMessageHandler(() =>
    CertificateHandler(clientCertificate));
builder.Services.AddHttpClient("core", client =>
{
    client.BaseAddress = new Uri(Required(builder.Configuration, "Core:BaseUrl"));
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() => CertificateHandler(clientCertificate));
builder.Services.AddScoped<DelegatedCoreTokenProvider>();
builder.Services.AddSingleton<DelegatedCoreTokenCache>();

WebApplication app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = context =>
    {
        string cache = context.File.Name.Equals("index.html", StringComparison.OrdinalIgnoreCase)
            ? "no-cache" : "public,max-age=31536000,immutable";
        context.Context.Response.Headers.CacheControl = cache;
    }
});
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
    await next();
});

app.MapHealthChecks("/healthz");
app.MapGet("/bff/login", (string? returnUrl) => Results.Challenge(
    new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) },
    [OpenIdConnectDefaults.AuthenticationScheme]));
app.MapPost("/bff/logout", async (HttpContext context, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(context);
    return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" },
        [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]);
}).RequireAuthorization();
app.MapGet("/bff/session", (ClaimsPrincipal user) => Results.Ok(new
{
    subject = user.FindFirstValue("sub"),
    name = user.FindFirstValue("name") ?? user.Identity?.Name,
    tenantId = user.FindFirstValue("tenant_id"),
    environmentId = user.FindFirstValue("environment_id"),
    scopes = user.FindAll("scope").SelectMany(value => value.Value.Split(' ')).Distinct()
})).RequireAuthorization();
app.MapGet("/bff/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
{
    AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { requestToken = tokens.RequestToken, headerName = "X-Certael-CSRF" });
}).RequireAuthorization();

RouteGroupBuilder cases = app.MapGroup("/bff/api/cases").RequireAuthorization();
cases.MapGet("/", ForwardGet);
cases.MapGet("/page", ForwardGet);
cases.MapGet("/{caseId:guid}", ForwardGet);
cases.MapPost("/{caseId:guid}/assignment", ForwardMutation);
cases.MapPost("/{caseId:guid}/notes", ForwardMutation);
cases.MapPost("/{caseId:guid}/transition", ForwardMutation);
cases.MapPost("/{caseId:guid}/actions", ForwardMutation);
cases.MapPut("/{caseId:guid}/metadata", ForwardPut);

RouteGroupBuilder caseSettings = app.MapGroup("/bff/api/case-settings").RequireAuthorization();
caseSettings.MapGet("/", ForwardGet);
caseSettings.MapPut("/categories/{key}", ForwardPut);
caseSettings.MapPut("/metadata/{key}", ForwardPut);

RouteGroupBuilder evidence = app.MapGroup("/bff/api/evidence").RequireAuthorization();
evidence.MapGet("/page", ForwardGet);
evidence.MapGet("/{verdictId:guid}", ForwardGet);

app.Map("/bff/{**path}", () => Results.NotFound());
app.MapFallbackToFile("index.html");

await app.RunAsync();

static async Task<IResult> ForwardGet(HttpContext context,
    IHttpClientFactory clients, DelegatedCoreTokenProvider tokens,
    CancellationToken cancellationToken) => await ForwardAsync(
        context, clients, tokens, HttpMethod.Get, cancellationToken);

static async Task<IResult> ForwardMutation(HttpContext context,
    IHttpClientFactory clients, DelegatedCoreTokenProvider tokens, IAntiforgery antiforgery,
    CancellationToken cancellationToken)
{
    await antiforgery.ValidateRequestAsync(context);
    return await ForwardAsync(context, clients, tokens, HttpMethod.Post, cancellationToken);
}

static async Task<IResult> ForwardPut(HttpContext context,
    IHttpClientFactory clients, DelegatedCoreTokenProvider tokens, IAntiforgery antiforgery,
    CancellationToken cancellationToken)
{
    await antiforgery.ValidateRequestAsync(context);
    return await ForwardAsync(context, clients, tokens, HttpMethod.Put, cancellationToken);
}

static async Task<IResult> ForwardAsync(HttpContext context, IHttpClientFactory clients,
    DelegatedCoreTokenProvider tokens, HttpMethod method, CancellationToken cancellationToken)
{
    string corePath = context.Request.Path.Value!.Replace("/bff/api", "/v1", StringComparison.Ordinal)
        + context.Request.QueryString;
    using var request = new HttpRequestMessage(method, corePath);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer",
        await tokens.GetAsync(cancellationToken));
    request.Headers.TryAddWithoutValidation("X-Certael-Operator", context.User.FindFirstValue("sub"));
    if (method != HttpMethod.Get)
        request.Content = new StreamContent(context.Request.Body)
        { Headers = { ContentType = MediaTypeHeaderValue.Parse(
            context.Request.ContentType ?? "application/json") } };
    using HttpResponseMessage response = await clients.CreateClient("core")
        .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
    context.Response.StatusCode = (int)response.StatusCode;
    context.Response.ContentType = response.Content.Headers.ContentType?.ToString()
        ?? "application/problem+json";
    await context.Response.Body.WriteAsync(body, cancellationToken);
    return Results.Empty;
}

static SocketsHttpHandler CertificateHandler(X509Certificate2 certificate)
{
    var handler = new SocketsHttpHandler();
    handler.SslOptions.ClientCertificates = new X509CertificateCollection { certificate };
    handler.PooledConnectionLifetime = TimeSpan.FromMinutes(5);
    return handler;
}

static X509Certificate2 LoadClientCertificate(IConfiguration configuration)
{
    string path = Required(configuration, "WorkloadIdentity:CertificatePath");
    string? password = configuration["WorkloadIdentity:CertificatePassword"];
    return X509CertificateLoader.LoadPkcs12FromFile(path, password,
        X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
}

static void LoadExternalConfiguration(WebApplicationBuilder builder)
{
    string? configured = Environment.GetEnvironmentVariable("CERTAEL_CONSOLE_CONFIG");
    if (string.IsNullOrWhiteSpace(configured)) return;
    string path = Path.GetFullPath(configured);
    var file = new FileInfo(path);
    if (!file.Exists || file.Length is <= 0 or > 1024 * 1024 || file.LinkTarget is not null
        || !string.Equals(file.Extension, ".json", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("CERTAEL_CONSOLE_CONFIG must name a regular JSON file no larger than 1 MiB.");
    builder.Configuration.AddJsonFile(path, optional: false, reloadOnChange: false);
    builder.Configuration.AddEnvironmentVariables();
}

static string Required(IConfiguration configuration, string key) =>
    configuration[key] is { Length: > 0 } value ? value
        : throw new InvalidOperationException($"{key} is required.");

static string SafeReturnUrl(string? value) =>
    value is { Length: > 0 } && value.StartsWith('/') && !value.StartsWith("//") ? value : "/";

public sealed class DelegatedCoreTokenProvider(
    IHttpContextAccessor accessor, IHttpClientFactory clients, IConfiguration configuration,
    X509Certificate2 certificate, DelegatedCoreTokenCache cache, TimeProvider clock)
{
    public async Task<string> GetAsync(CancellationToken cancellationToken)
    {
        HttpContext context = accessor.HttpContext
            ?? throw new InvalidOperationException("No active operator request.");
        string subjectToken = await context.GetTokenAsync("access_token")
            ?? throw new InvalidOperationException("The operator session has no access token.");
        string audience = configuration["TokenExchange:Audience"]
            ?? configuration["Core:Audience"] ?? "certael-api";
        string scopes = configuration["TokenExchange:Scopes"]
            ?? "evidence:read cases:read cases:write cases:act privacy:export";
        string cacheKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{subjectToken}\0{audience}\0{scopes}\0{certificate.Thumbprint}")));
        return await cache.GetAsync(cacheKey, clock.GetUtcNow(), async () =>
        {
            DelegatedToken exchanged = await ExchangeAsync(subjectToken, audience, scopes,
                cancellationToken);
            if (!DelegatedTokenBinding.IsBoundToCertificate(exchanged.AccessToken, certificate))
                throw new InvalidOperationException(
                    "Token exchange returned an access token that is not bound to the configured workload certificate.");
            return exchanged;
        }, cancellationToken);
    }

    private async Task<DelegatedToken> ExchangeAsync(string subjectToken, string audience,
        string scopes, CancellationToken cancellationToken)
    {
        string clientId = configuration["TokenExchange:ClientId"]
            ?? Required(configuration, "Authentication:ClientId");
        string clientSecret = configuration["TokenExchange:ClientSecret"]
            ?? Required(configuration, "Authentication:ClientSecret");
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["subject_token"] = subjectToken,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["audience"] = audience,
            ["scope"] = scopes
        };
        using HttpResponseMessage response = await clients.CreateClient("token-exchange")
            .PostAsync(TokenEndpoint(configuration),
                new FormUrlEncodedContent(form), cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Delegated token exchange failed with HTTP {(int)response.StatusCode}.");
        using JsonDocument payload = JsonDocument.Parse(
            await response.Content.ReadAsStreamAsync(cancellationToken));
        string accessToken = payload.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Token exchange returned no access token.");
        int expiresIn = payload.RootElement.TryGetProperty("expires_in", out JsonElement expiry)
            && expiry.TryGetInt32(out int seconds) ? seconds : 0;
        if (expiresIn is < 60 or > 86_400)
            throw new InvalidOperationException("Token exchange returned an invalid lifetime.");
        return new DelegatedToken(accessToken, clock.GetUtcNow().AddSeconds(expiresIn));
    }

    private static string TokenEndpoint(IConfiguration configuration)
    {
        if (configuration["TokenExchange:Endpoint"] is { Length: > 0 } endpoint)
            return endpoint;
        if (configuration["Authentication:TokenEndpoint"] is { Length: > 0 } legacy)
            return legacy;
        return Required(configuration, "Authentication:Authority").TrimEnd('/') + "/oauth/token";
    }

    private static string Required(IConfiguration configuration, string key) =>
        configuration[key] is { Length: > 0 } value ? value
            : throw new InvalidOperationException($"{key} is required.");
}

public sealed record DelegatedToken(string AccessToken, DateTimeOffset ExpiresAt);

public static class DelegatedTokenBinding
{
    public static bool IsBoundToCertificate(string token, X509Certificate2 certificate)
    {
        string[] parts = token.Split('.');
        if (parts.Length != 3 || parts[1].Length > 64 * 1024) return false;
        try
        {
            string padded = parts[1].Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            using JsonDocument payload = JsonDocument.Parse(Convert.FromBase64String(padded));
            if (!payload.RootElement.TryGetProperty("cnf", out JsonElement confirmation)
                || !confirmation.TryGetProperty("x5t#S256", out JsonElement thumbprint)
                || thumbprint.GetString() is not { } supplied)
                return false;
            string expected = Convert.ToBase64String(SHA256.HashData(certificate.RawData))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            byte[] left = Encoding.ASCII.GetBytes(supplied);
            byte[] right = Encoding.ASCII.GetBytes(expected);
            return left.Length == right.Length
                && CryptographicOperations.FixedTimeEquals(left, right);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return false;
        }
    }
}

public sealed class DelegatedCoreTokenCache
{
    private sealed record Entry(string AccessToken, DateTimeOffset ExpiresAt);
    private readonly ConcurrentDictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> locks = new(StringComparer.Ordinal);

    public async Task<string> GetAsync(string key, DateTimeOffset now,
        Func<Task<DelegatedToken>> factory, CancellationToken cancellationToken)
    {
        if (entries.TryGetValue(key, out Entry? current)
            && current.ExpiresAt > now.AddMinutes(1))
            return current.AccessToken;
        SemaphoreSlim gate = locks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (entries.TryGetValue(key, out current)
                && current.ExpiresAt > now.AddMinutes(1))
                return current.AccessToken;
            DelegatedToken created = await factory();
            entries[key] = new Entry(created.AccessToken, created.ExpiresAt);
            if (entries.Count > 10_000) Purge(now);
            return created.AccessToken;
        }
        finally
        {
            gate.Release();
        }
    }

    private void Purge(DateTimeOffset now)
    {
        foreach ((string key, Entry value) in entries)
        {
            if (value.ExpiresAt <= now) entries.TryRemove(key, out _);
        }
        foreach ((string key, SemaphoreSlim _) in locks)
        {
            if (!entries.ContainsKey(key) && locks.TryRemove(key, out SemaphoreSlim? removed))
                removed.Dispose();
        }
    }
}

public partial class Program;

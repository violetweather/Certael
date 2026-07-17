using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Antiforgery;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
builder.Services.AddHttpContextAccessor();
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
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"];
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
builder.Services.AddHttpClient("token-exchange").ConfigurePrimaryHttpMessageHandler(() =>
    CertificateHandler(clientCertificate));
builder.Services.AddHttpClient("core", client =>
{
    client.BaseAddress = new Uri(Required(builder.Configuration, "Core:BaseUrl"));
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() => CertificateHandler(clientCertificate));
builder.Services.AddScoped<DelegatedCoreTokenProvider>();

WebApplication app = builder.Build();
app.UseExceptionHandler();
app.UseHttpsRedirection();
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
cases.MapGet("/{caseId:guid}", ForwardGet);
cases.MapPost("/{caseId:guid}/assignment", ForwardMutation);
cases.MapPost("/{caseId:guid}/notes", ForwardMutation);
cases.MapPost("/{caseId:guid}/transition", ForwardMutation);
cases.MapPost("/{caseId:guid}/actions", ForwardMutation);

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

static string Required(IConfiguration configuration, string key) =>
    configuration[key] is { Length: > 0 } value ? value
        : throw new InvalidOperationException($"{key} is required.");

static string SafeReturnUrl(string? value) =>
    value is { Length: > 0 } && value.StartsWith('/') && !value.StartsWith("//") ? value : "/";

public sealed class DelegatedCoreTokenProvider(
    IHttpContextAccessor accessor, IHttpClientFactory clients, IConfiguration configuration)
{
    public async Task<string> GetAsync(CancellationToken cancellationToken)
    {
        HttpContext context = accessor.HttpContext
            ?? throw new InvalidOperationException("No active operator request.");
        string subjectToken = await context.GetTokenAsync("access_token")
            ?? throw new InvalidOperationException("The operator session has no access token.");
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["subject_token"] = subjectToken,
            ["audience"] = configuration["Core:Audience"] ?? "certael-api",
            ["scope"] = "evidence:read cases:read cases:write cases:act privacy:export"
        };
        using HttpResponseMessage response = await clients.CreateClient("token-exchange")
            .PostAsync(Required(configuration, "Authentication:TokenEndpoint"),
                new FormUrlEncodedContent(form), cancellationToken);
        response.EnsureSuccessStatusCode();
        using JsonDocument payload = JsonDocument.Parse(
            await response.Content.ReadAsStreamAsync(cancellationToken));
        return payload.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Token exchange returned no access token.");
    }

    private static string Required(IConfiguration configuration, string key) =>
        configuration[key] is { Length: > 0 } value ? value
            : throw new InvalidOperationException($"{key} is required.");
}

public partial class Program;

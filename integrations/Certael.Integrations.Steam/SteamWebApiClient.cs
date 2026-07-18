using System.Net;
using System.Text.Json;
using Certael.Server.Integrations;

namespace Certael.Integrations.Steam;

/// <summary>Bounded client for Steamworks AuthenticateUserTicket.</summary>
public sealed class SteamWebApiClient : ISteamWebApiClient
{
    private const int MaximumResponseBytes = 1024 * 1024;
    private readonly HttpClient _client;
    private readonly string _publisherWebApiKey;

    public SteamWebApiClient(HttpClient client, string publisherWebApiKey)
    {
        _client = client;
        if (string.IsNullOrWhiteSpace(publisherWebApiKey)
            || publisherWebApiKey.Length is < 16 or > 512
            || publisherWebApiKey.Any(char.IsControl))
            throw new ArgumentException("Steam publisher Web API key is invalid.",
                nameof(publisherWebApiKey));
        _publisherWebApiKey = publisherWebApiKey;
        _client.BaseAddress ??= new Uri("https://partner.steam-api.com/");
        if (_client.BaseAddress.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Steam Web API base address must use HTTPS.",
                nameof(client));
        if (_client.Timeout <= TimeSpan.Zero || _client.Timeout > TimeSpan.FromSeconds(30))
            _client.Timeout = TimeSpan.FromSeconds(10);
    }

    public async ValueTask<SteamAuthenticationResult> AuthenticateUserTicketAsync(
        string applicationId, byte[] ticket, CancellationToken cancellationToken)
    {
        if (applicationId.Length is < 1 or > 20 || !applicationId.All(char.IsAsciiDigit)
            || ticket is null or { Length: < 1 or > 16 * 1024 })
            throw new IntegrationException("INVALID_STEAM_TICKET",
                "Steam ticket request is invalid.");
        string path = "ISteamUserAuth/AuthenticateUserTicket/v1/?key="
            + Uri.EscapeDataString(_publisherWebApiKey) + "&appid="
            + Uri.EscapeDataString(applicationId) + "&ticket="
            + Convert.ToHexString(ticket).ToLowerInvariant();
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Accept.ParseAdd("application/json");
        HttpResponseMessage response;
        try
        {
            response = await _client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new IntegrationException("STEAM_UNAVAILABLE",
            "Steam identity verification timed out."); }
        catch (HttpRequestException)
        { throw new IntegrationException("STEAM_UNAVAILABLE",
            "Steam identity verification is unavailable."); }
        using (response)
        {
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new IntegrationException("STEAM_CREDENTIAL_REJECTED",
                "Steam rejected the publisher credential.");
        if (!response.IsSuccessStatusCode)
            throw new IntegrationException("STEAM_UNAVAILABLE",
                "Steam identity verification is unavailable.");
        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            throw new IntegrationException("STEAM_INVALID_RESPONSE",
                "Steam response exceeded its size limit.");
        byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (body.Length is < 1 or > MaximumResponseBytes)
            throw new IntegrationException("STEAM_INVALID_RESPONSE",
                "Steam response size is invalid.");
        try
        {
            using JsonDocument document = JsonDocument.Parse(body,
                new JsonDocumentOptions { MaxDepth = 16, CommentHandling = JsonCommentHandling.Disallow });
            JsonElement parameters = document.RootElement.GetProperty("response")
                .GetProperty("params");
            string result = parameters.GetProperty("result").GetString() ?? string.Empty;
            if (!string.Equals(result, "OK", StringComparison.Ordinal))
                return new SteamAuthenticationResult(false, string.Empty, applicationId, body);
            string steamId = parameters.GetProperty("steamid").GetString() ?? string.Empty;
            if (steamId.Length is < 1 or > 32 || !steamId.All(char.IsAsciiDigit))
                throw new JsonException("Steam ID is invalid.");
            return new SteamAuthenticationResult(true, steamId, applicationId, body);
        }
        catch (Exception exception) when (exception is JsonException
            or InvalidOperationException or KeyNotFoundException)
        {
            throw new IntegrationException("STEAM_INVALID_RESPONSE",
                "Steam returned a malformed identity response.", exception);
        }
        }
    }
}

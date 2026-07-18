using System.Security.Cryptography;
using System.Text;
using Certael.Server.Integrations;
using StackExchange.Redis;

namespace Certael.Persistence.Redis;

public sealed class RedisPlatformProofReplayStore(IConnectionMultiplexer connection,
    TimeProvider clock, string keyPrefix = "certael") : IPlatformProofReplayStore
{
    public async ValueTask<bool> TryReserveAsync(string replayKey, DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TimeSpan lifetime = expiresAt - clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(replayKey) || replayKey.Length > 512
            || lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(10)) return false;
        string digest = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(replayKey))).ToLowerInvariant();
        IDatabase database = connection.GetDatabase();
        return await database.StringSetAsync($"{keyPrefix}:platform-proof:{digest}", "1",
            lifetime, When.NotExists, CommandFlags.DemandMaster);
    }
}

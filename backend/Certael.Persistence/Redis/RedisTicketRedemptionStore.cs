using Certael.Server.Sessions;
using StackExchange.Redis;
using System.Security.Cryptography;
using System.Text;

namespace Certael.Persistence.Redis;

public sealed class RedisTicketRedemptionStore(IConnectionMultiplexer connection, string keyPrefix = "certael")
    : ITicketRedemptionStore
{
    public async ValueTask<bool> TryRedeemAsync(string tenantId, string environmentId,
        Guid ticketId, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TimeSpan lifetime = expiresAt - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        if (lifetime <= TimeSpan.Zero) return false;
        IDatabase database = connection.GetDatabase();
        string namespaceId = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{tenantId}\0{environmentId}")));
        return await database.StringSetAsync(
            $"{keyPrefix}:{namespaceId}:redeemed:{ticketId:N}", "1", lifetime,
            When.NotExists, CommandFlags.DemandMaster);
    }
}

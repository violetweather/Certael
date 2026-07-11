using Certael.Server.Sessions;
using StackExchange.Redis;

namespace Certael.Persistence.Redis;

public sealed class RedisTicketRedemptionStore(IConnectionMultiplexer connection, string keyPrefix = "certael")
    : ITicketRedemptionStore
{
    public async ValueTask<bool> TryRedeemAsync(Guid ticketId, DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TimeSpan lifetime = expiresAt - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        if (lifetime <= TimeSpan.Zero) return false;
        IDatabase database = connection.GetDatabase();
        return await database.StringSetAsync(
            $"{keyPrefix}:redeemed:{ticketId:N}", "1", lifetime, When.NotExists, CommandFlags.DemandMaster);
    }
}

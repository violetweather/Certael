using System.Security.Cryptography;
using System.Text;
using Certael.Server.Economy;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Certael.AnalyticsWorker;

/// <summary>Idempotent, bounded rolling indexes for low-latency economy windows.</summary>
public sealed class RedisEconomyProjection(IConnectionMultiplexer redis,
    IOptions<AnalyticsWorkerOptions> options)
{
    private const string ProjectScript = """
        local present = redis.call('ZSCORE', KEYS[1], ARGV[1])
        if present then return 0 end
        redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[3])
        local count = redis.call('ZCARD', KEYS[1])
        local maximum = tonumber(ARGV[4])
        if count > maximum then
          redis.call('ZPOPMIN', KEYS[1], count - maximum)
        end
        redis.call('EXPIRE', KEYS[1], ARGV[5])
        return 1
        """;

    private readonly AnalyticsWorkerOptions _options = options.Value;

    public async ValueTask ProjectAsync(EconomyEventV1 value,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IDatabase database = redis.GetDatabase();
        long occurred = value.OccurredAt.ToUnixTimeMilliseconds();
        long cutoff = (value.OccurredAt - TimeSpan.FromDays(_options.RedisEconomyRetentionDays))
            .ToUnixTimeMilliseconds();
        int ttl = checked(_options.RedisEconomyRetentionDays * 24 * 60 * 60);
        string boundary = Digest($"{value.TenantId}\0{value.GameId}\0{value.EnvironmentId}");
        var projections = new List<(RedisKey Key, string Member)>
        {
            ($"certael:economy:v1:{boundary}:player:{Digest(value.PlayerSubject)}",
                value.EventId.ToString("N"))
        };
        if (value.Transaction is not null)
        {
            for (int index = 0; index < value.Transaction.Lines.Count; index++)
            {
                EconomyLedgerLine line = value.Transaction.Lines[index];
                projections.Add(($"certael:economy:v1:{boundary}:account:{Digest(line.AccountId)}",
                    $"{value.EventId:N}:{index}"));
            }
        }
        else
        {
            ItemLineageMutation mutation = value.ItemMutation!;
            projections.Add(($"certael:economy:v1:{boundary}:item:{Digest(mutation.ItemId)}",
                value.EventId.ToString("N")));
        }

        foreach ((RedisKey key, string member) in projections.Distinct())
        {
            cancellationToken.ThrowIfCancellationRequested();
            await database.ScriptEvaluateAsync(ProjectScript, [key],
            [
                member,
                occurred,
                cutoff,
                _options.RedisEconomyMaximumEntriesPerSubject,
                ttl
            ]);
        }
    }

    private static string Digest(string value) => Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}

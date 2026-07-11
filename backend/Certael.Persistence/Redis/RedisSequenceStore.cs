using Certael.Server.Actions;
using StackExchange.Redis;

namespace Certael.Persistence.Redis;

public sealed class RedisSequenceStore(
    IConnectionMultiplexer connection,
    TimeSpan sessionTtl,
    string keyPrefix = "certael") : IActionAdmissionStore
{
    private const string Script = """
        local sequence = redis.call('HGET', KEYS[1], 'sequence')
        if sequence and ARGV[1] <= sequence then return 'REPLAY_OR_REORDER' end
        local digest = redis.call('HGET', KEYS[1], 'digest')
        if not digest then digest = ARGV[2] end
        if digest ~= ARGV[3] then return 'ACTION_CHAIN_MISMATCH' end
        local count = redis.call('ZCOUNT', KEYS[2], ARGV[5], '+inf')
        if count >= tonumber(ARGV[6]) then return 'ACTION_RATE_LIMITED' end
        redis.call('HSET', KEYS[1], 'sequence', ARGV[1], 'digest', ARGV[4])
        redis.call('PEXPIRE', KEYS[1], ARGV[7])
        redis.call('ZADD', KEYS[2], ARGV[8], ARGV[1] .. ':' .. ARGV[4])
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[5])
        redis.call('PEXPIRE', KEYS[2], ARGV[7])
        return 'ALLOWED'
        """;

    public async ValueTask<ActionAdmissionDecision> TryAdmitAsync(ActionAdmission admission,
        ActionAdmissionPolicy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryActionAdmissionStore.Validate(admission, policy);
        if (sessionTtl <= TimeSpan.Zero || sessionTtl > TimeSpan.FromDays(1))
            throw new InvalidOperationException("Session TTL is invalid.");
        long now = admission.ReceivedAt.ToUnixTimeMilliseconds();
        long cutoff = now - checked((long)policy.Window.TotalMilliseconds);
        string zero = Convert.ToHexString(new byte[32]);
        RedisResult result = await connection.GetDatabase().ScriptEvaluateAsync(
            Script,
            [$"{keyPrefix}:admission:{admission.SessionId}",
                $"{keyPrefix}:rate:{admission.SessionId}:{admission.ActionType}"],
            [admission.Sequence.ToString("D20", System.Globalization.CultureInfo.InvariantCulture), zero,
                Convert.ToHexString(admission.PreviousDigest.Span), Convert.ToHexString(admission.ActionDigest.Span),
                cutoff.ToString(System.Globalization.CultureInfo.InvariantCulture),
                policy.MaximumActions.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ((long)sessionTtl.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture),
                now.ToString(System.Globalization.CultureInfo.InvariantCulture)],
            CommandFlags.DemandMaster);
        string reason = result.ToString();
        return reason == "ALLOWED" ? ActionAdmissionDecision.Allow() : ActionAdmissionDecision.Reject(reason);
    }
}

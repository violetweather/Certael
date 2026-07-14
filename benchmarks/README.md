# Certael benchmark evidence

Benchmark files are immutable observations with the command, hardware, result,
and explicit exclusions. A local protocol run is useful for regression detection
but does not satisfy the production load gate by itself.

The 2026-07-13 Apple M4 run created 100,000 independent sessions and performed
1,000,000 canonical action sign/verify cycles at 30,108.82 actions per second.
It exceeded the protocol-throughput target locally. It did not exercise the API,
Redis, PostgreSQL, authoritative game callbacks, replicas, failover, or a 24-hour
soak; those remain separate acceptance evidence.

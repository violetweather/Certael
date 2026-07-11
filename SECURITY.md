# Security policy

Do not file public issues for suspected vulnerabilities. Until a dedicated
security mailbox is provisioned, use a private GitHub security advisory on the
canonical repository. Include the affected version, reproduction, impact, and
suggested mitigation when possible.

Supported releases receive critical security fixes. Pre-release builds are not
supported for production use. Certael never asks researchers to access player
data, disrupt games, or test systems they do not own or have permission to test.

## Design invariants

1. Client claims never authorize persistent game-state mutation.
2. No production secret is embedded in a client binary.
3. Tickets are short-lived, audience-bound, proof-of-possession-bound, and
   single-use.
4. Duplicate action IDs return the original authoritative result.
5. Integrity telemetry alone cannot produce a permanent ban.
6. All enforcement remains developer-controlled.

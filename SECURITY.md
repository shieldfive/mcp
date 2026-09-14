# Security Policy

ShieldFive takes the security of `@shieldfive/mcp` seriously. This document
describes how to report a vulnerability, what we commit to, and the safe-harbor
terms for security researchers.

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.** Instead, email us
directly:

- **Email:** `security@shieldfive.com`
- **PGP key:** Not yet published. Encrypt with a temporary key on request, or
  send in plaintext — we would rather know about the issue than have it sit in
  your inbox.

If you cannot encrypt the report, send it in plaintext anyway. We will follow up
over an encrypted channel.

### What to include

1. A description of the vulnerability and its impact.
2. Steps to reproduce, including a minimal proof-of-concept if possible.
3. The server version and runtime environment (Node version, operating system).
4. Whether the issue is already public or has been disclosed elsewhere.
5. Your name and a way to contact you (or "anonymous" if you prefer).

## Our commitments

| Severity                     | Acknowledgement | Initial response | Patch target |
| ---------------------------- | :-------------: | :--------------: | :----------: |
| Critical (key/plaintext leak)|    24 hours     |     48 hours     |   7 days     |
| High (integrity bypass)      |    48 hours     |     5 days       |   14 days    |
| Medium (DoS, info leakage)   |    72 hours     |     7 days       |   30 days    |
| Low (defense-in-depth)       |    7 days       |     14 days      |   90 days    |

We will:

- Acknowledge your report within the windows above.
- Keep you informed of our investigation.
- Credit you in the release notes (with your permission, or anonymously).
- Coordinate public disclosure with you, defaulting to a 90-day window.
- Publish a CVE when appropriate.

We will *not*:

- Take legal action against researchers acting in good faith (see Safe Harbor).
- Demand silence as a condition of bounty or credit.

## Safe Harbor

Security research conducted in accordance with this policy is authorized. We will
not pursue civil claims or refer law enforcement against researchers who:

1. Make a good-faith effort to avoid privacy violations, data destruction, and
   service interruption.
2. Do not access, modify, or exfiltrate data belonging to anyone other than
   themselves or research accounts.
3. Report the vulnerability promptly through this policy's channels.
4. Do not exploit the vulnerability beyond what is necessary to confirm it.
5. Do not publicly disclose before we have had a reasonable opportunity to
   remediate (the timelines above).

## Bug bounty

ShieldFive operates a paid bug bounty program. For current scope, reward tiers,
rules of engagement, and submission instructions, see
https://shieldfive.com/security/bug-bounty.

## Scope

In scope: this CLI — the way it derives keys, encrypts files and filenames,
constructs the upload proof, and transmits data. A demonstration that plaintext
or key material can leak from this client is the highest-value report.

Out of scope for *this* repository (report elsewhere or not at all):

- Vulnerabilities in the cryptographic core — report those against
  [`@shieldfive/crypto`](https://github.com/shieldfive/crypto).
- Vulnerabilities in dependencies (`@noble/*`, `@supabase/supabase-js`) — report
  those upstream.
- Server-side issues in the ShieldFive backend — report via the bug bounty
  program above.
- Attacks that require an attacker to already control the user's device.

## Threat model for this package

This server runs on the user's own machine, speaks MCP over stdio, and is driven
by an AI assistant. The assistant is **not** trusted to choose safe paths — that
is the point of containment — but it is trusted not to be actively adversarial,
because it already runs with the user's privileges through every other tool it
has.

In scope, and what is done about each:

| Concern | Mitigation |
|---|---|
| A path argument escaping the allowed roots | Every path is `realpath`-resolved before use and must land inside a configured root. Separator-aware boundary test. Tested on both the read and the write side. |
| A symlink inside a root pointing out of it | Resolved before the containment check; the directory walk uses `lstat` and never traverses a link. |
| A destination under a symlinked parent | The nearest existing ancestor is resolved and the remaining segments re-appended before the write. |
| Irreversible deletion | Nothing is unlinked. `trash_local` moves within the same root and writes a restore manifest. |
| An assistant acting without the user seeing the plan | Mutating tools are inert without `confirm: true` and return the plan instead. |
| Credential exposure | No credential is read, stored or inherited. `SHIELDFIVE_MCP_ROOTS` is the only environment variable this code reads, asserted by a test. |
| Exfiltration over the network | No networking module is imported and `fetch` is never called, asserted by a test. The transport is stdio. |
| Credential exposure via a subprocess | No subprocess is spawned. Spawning `sf` would inherit `SF_PASSWORD` from the environment whether or not this code names it, so the ban is on spawning at all. |

Out of scope, stated rather than implied:

- **Time-of-check to time-of-use.** An attacker able to swap a directory for a
  symlink between the containment check and the filesystem call can defeat it.
  Closing this needs `openat2`-style primitives that Node does not expose. It
  presupposes write access inside a root, which is already a compromise of the
  thing being protected.
- **What the assistant does with the output.** File paths are returned to the
  model. If a path is itself sensitive, the root it sits in should not be given
  to this server.
- **The dependency tree.** The no-network assertion covers this package's own
  source. `@modelcontextprotocol/sdk` contains HTTP transports for other
  servers; this one imports only the stdio transport, which is asserted.

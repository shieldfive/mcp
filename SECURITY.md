# Security policy

`@shieldfive/mcp` runs on a user's own machine, reads and writes files in
directories they name, and is driven by an AI assistant. Its security properties
are mostly about containment and about not holding things it does not need.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.** Email
`security@shieldfive.com`.

There is no PGP key published. Encrypt with a temporary key on request, or send
in plaintext — a report that arrives is worth more than one that waits for key
exchange.

Include what you have: a description and its impact, steps to reproduce, the
package version and your Node version and operating system, whether the issue is
already public, and how you would like to be credited.

### What to expect

| Severity | Acknowledged | First substantive reply | Fix target |
|---|---|---|---|
| Critical — data loss, or reads/writes outside the configured roots | 1 working day | 3 working days | 7 days |
| High | 2 working days | 5 working days | 30 days |
| Medium / Low | 5 working days | 10 working days | next release |

**There is no bug bounty.** ShieldFive ran one until 2026-07; it closed, and
`/security/bug-bounty` redirects to the security page. Reports are answered and
credited if you want credit, and they are not paid. That is a complete answer,
stated here so nobody spends time on the assumption that it is otherwise.

### Safe harbour

Research conducted in good faith against your own installation, staying within
your own files and the limits below, will not be treated as a hostile act. Do
not access data belonging to anyone else, do not degrade a service, and give us
a reasonable window before publishing.

## Scope

In scope: this package's own source — path containment, the walk, the mutating
tools, the trash, the MCP surface, and the claims its README makes.

Out of scope for this repository, with the right destination:

- The ShieldFive vault, web application and API — `security@shieldfive.com`,
  same address, different codebase.
- `@shieldfive/crypto` — its own repository. **This package does not depend on
  it**, and a test asserts no `@shieldfive/*` or `@supabase/*` package is a
  dependency.
- `@modelcontextprotocol/sdk` and `zod`, this package's only two dependencies —
  report upstream. A vulnerability in how *this* package uses them is in scope.

## Threat model

The assistant driving this server is **not** trusted to choose safe paths; that
is what containment is for. It is assumed not to be actively adversarial,
because it already runs with the user's privileges through every other tool it
has.

| Concern | What is done | Tested |
|---|---|---|
| A path argument escaping the allowed roots | Every path is `realpath`-resolved before use and must land inside a configured root; separator-aware boundary test | yes |
| A symlink inside a root pointing out of it | Resolved before the containment check; the walk uses `lstat` and never traverses a link | yes, read and write side |
| A destination under a symlinked parent | Nearest existing ancestor resolved, remaining segments re-appended, checked before the write | yes |
| Irreversible deletion | Nothing is unlinked. `trash_local` moves within the root; an overwriting `move_local` moves the displaced item to the trash rather than removing it | yes |
| A partial failure losing track of moved files | The trash manifest is written after each item, not once at the end, and a partial failure reports where the moved items went | yes |
| An assistant acting without the user seeing the plan | Mutating tools are inert without `confirm: true` and report what they would displace as well as what they would move | yes |
| Credential exposure in this code | No credential is read or stored. `SHIELDFIVE_MCP_ROOTS` is the only environment variable read | yes |
| Exfiltration over the network | No networking module imported, `fetch` never called; the transport is stdio | yes, for this package's source |
| Credential exposure via a subprocess | No subprocess is spawned at all. Spawning `sf` would inherit `SF_PASSWORD` from the environment whether or not this code named it | yes |

## Known limits

Stated because a threat model that lists only what it handles is misleading.

- **Time-of-check to time-of-use.** Containment resolves a path and then acts on
  it. An attacker who can replace a directory with a symlink between those two
  steps defeats it. The window is kept narrow — the destination is re-resolved
  immediately before a write, rather than before the tree measurement that
  precedes it — but it is not closed, and closing it needs `openat2`-style
  primitives Node does not expose. It presupposes write access inside a root,
  which is already a compromise of the thing being protected.
- **Hardlinks are not resolved.** `realpath` follows symlinks, not hardlinks, so
  a hardlink inside a root that references an inode also reachable outside every
  root reads as contained, because it genuinely is one of that inode's names.
  Files with a link count above one are counted and reported in scan warnings
  rather than silently trusted.
- **The environment is inherited, like any child process.** This code reads only
  `SHIELDFIVE_MCP_ROOTS`, and that is asserted. It does not follow that other
  variables are absent from the process: if the user exported `SF_PASSWORD` for
  `@shieldfive/cli` in the shell that launched their MCP client, it is in this
  process's address space, as it is in every other tool that client spawns. What
  this package guarantees is that it never reads, stores, forwards or spawns
  anything with it.
- **The no-network assertion covers this package's source, not its dependency
  tree.** `@modelcontextprotocol/sdk` ships HTTP transports for other people's
  servers. This one imports the stdio transport and no HTTP transport, which is
  asserted; the source scan matches import specifiers, so a computed dynamic
  import would evade it.
- **File paths reach the model.** If a path is itself sensitive, do not give
  this server the root it sits in.
- **Windows is untested.** No POSIX-only API is used and paths go through
  `node:path`, but nobody has run it there.

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
| High — the `confirm: true` gate failing open, or a claim in the README the code does not honour | 2 working days | 5 working days | 30 days |
| Medium / Low — everything else, including a result that is wrong rather than unsafe | 5 working days | 10 working days | next release |

**There is no bug bounty.** ShieldFive ran one until 2026-07; it closed, and
`/security/bug-bounty` redirects to the security page. Reports are answered and
credited on request. They are not paid.

### Safe harbour

This server runs on your machine against your own files, so there is no service
to degrade and nobody else's data to reach. Research against your own
installation is welcome and we will not pursue legal action over it. Give us 90
days from your first report before publishing, or less if we have already
shipped the fix.

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
| A path argument escaping the allowed roots | Every path is used exactly as given — nothing is trimmed — and `realpath`-resolved before use; it must land inside a configured root, by a separator-aware boundary test | yes |
| A symlink inside a root pointing out of it | Resolved before the containment check for anything read or written through; the walk uses `lstat` and never traverses a link | yes, read and write side |
| A symlink given as the item to move, rename or trash | The link itself is acted on, never its target; containment is checked on the link's own position | yes |
| A dangling symlink on a write path | Refused (`dangling_symlink`) wherever a write would pass through it. At a destination it is an existing entry: shown in the preview, refused without `overwrite`, and moved to the trash itself with it | yes, including across devices |
| A destination under a symlinked parent | Nearest existing ancestor resolved, remaining segments re-appended, checked before the write | yes |
| The trash directory redirected by a symlink | `.shieldfive-mcp-trash` is `lstat`'d while planning, then created one level at a time without following anything and checked again before anything moves in; a link or a non-directory there is refused (`trash_unsafe`) | yes |
| The trash on a different volume from the item | An item's trash is in the highest directory between it and its root on the item's own device; a move into the trash is a rename and never a copy; a mount point cannot be trashed (`trash_no_same_volume`) | yes, on a RAM disk |
| Irreversible deletion | Nothing of the user's is removed except the source of a move that crosses a device, after its copy is verified. `trash_local` renames; an overwriting `move_local` moves the displaced item to the trash | yes |
| A cross-device move losing data | The copy is made under a fresh, exclusively created name; symlinks and special files in the tree are refused; each file is flushed and verified by size and SHA-256 against a source that has not changed; the source is removed entry by entry, and only what is unchanged since it was copied | yes, on a RAM disk, with a corrupt copy and a changing source injected |
| A rename or move replacing something | Operations that fail when the destination exists: a hard link then an unlink for files, a recreated symlink, a rename over an empty placeholder for directories | yes, with the race injected |
| A partial failure losing track of moved files | Each call has its own batch directory; its manifest lists every item before any moves, is written atomically and one write at a time, and a partial failure names each moved item and its manifest, with the detail returned to the client | yes |
| A corrupt or foreign manifest being overwritten | No existing manifest is read, merged or replaced; the first write of a manifest fails if anything is at its name | yes |
| An assistant acting without the user seeing the plan | Mutating tools are inert without `confirm: true` and report what they would displace as well as what they would move | yes |
| An oversized argument | `limit`, `max_files`, `max_files_hashed`, `paths`, path length and `new_name` are capped at the MCP schema and again in the handler; values echoed in a refusal are cut short | yes |
| A cancelled request still changing files | Nothing starts once a request is cancelled; a trash batch stops between items and says what moved; the outcome is logged, because the SDK sends no response to a cancelled request | yes |
| Credential exposure in this code | No credential is read or stored. `SHIELDFIVE_MCP_ROOTS` is the only environment variable read | yes |
| Exfiltration over the network | No networking module imported, `fetch` never called; the transport is stdio | yes, for this package's source |
| Credential exposure via a subprocess | No subprocess is spawned at all. Spawning `sf` would inherit `SF_PASSWORD` from the environment whether or not this code named it | yes |

## Known limits

- **A confirmed call is not bound to its preview.** `confirm: true` plans the
  operation again from scratch and acts on that plan. Nothing ties it to the
  preview the user approved, so if the tree changed between the two calls, what
  is done can differ from what was shown. Binding them with a token over the
  paths and their modification times is the next design step; it is not built.
- **Time-of-check to time-of-use.** Containment resolves a path and then acts on
  it. An attacker who can replace a directory with a symlink between those two
  steps defeats it. The window is kept narrow — a destination is re-resolved
  immediately before a write, and the trash directory is checked again after it
  is created — but it is not closed, and closing it needs `openat2`-style
  primitives Node does not expose. It presupposes write access inside a root,
  which is already a compromise of the thing being protected.
- **"Never replaces" has a residual window in two places.** Node exposes neither
  `renameat2(RENAME_NOREPLACE)` nor `renamex_np(RENAME_EXCL)`. A directory is
  renamed over an empty placeholder made a moment before, so an *empty*
  directory created in its place in that instant would be replaced, which loses
  nothing. FIFOs, sockets and device files, filesystems without hard links (FAT,
  exFAT, some network shares) and directories on Windows fall back to checking
  and then renaming, where a file created at the destination in between would
  be replaced.
- **Hardlinks are not resolved.** `realpath` follows symlinks, not hardlinks, so
  a hardlink inside a root that references an inode also reachable outside every
  root reads as contained, because it genuinely is one of that inode's names.
  Files with a link count above one are counted and reported in scan warnings
  rather than silently trusted. `find_duplicates` counts names of one inode as
  one copy; the totals in `list_local` and `storage_summary` count every name.
- **APFS clones are invisible.** A clone shares storage with its original but is
  a separate file that nothing readable distinguishes from a real copy, so
  `find_duplicates` reports clones as reclaimable when trashing one frees little
  or nothing.
- **A cross-device move is as durable as the drive.** Each copied file is flushed
  with `fsync` and verified before its original is removed, and directory
  flushes are attempted, but how much a flush guarantees is up to the drive and
  the filesystem. A crash during a copy can leave a partial copy under a hidden
  `.shieldfive-mcp-incoming-*` name beside the destination; the source is intact
  until its copy is in place.
- **Cancellation cannot always stop a move.** A move is rolled back if it is
  cancelled before its source starts being removed, and completed if after. The
  MCP SDK sends no response to a cancelled request, so the outcome of a
  cancelled mutation is written to this server's stderr log — and, for the
  trash, to the manifest — rather than returned.
- **The environment is inherited, like any child process.** This code reads only
  `SHIELDFIVE_MCP_ROOTS`, and that is asserted. It does not follow that other
  variables are absent from the process: if the user exported `SF_PASSWORD` for
  `@shieldfive/cli` in the shell that launched their MCP client, it is in this
  process's address space, as it is in every other tool that client spawns. This
  package never reads it, never stores it, and spawns no subprocess that could
  inherit it.
- **The no-network assertion covers this package's source, not its dependency
  tree.** `@modelcontextprotocol/sdk` ships HTTP transports for other people's
  servers. This one imports the stdio transport and no HTTP transport, which is
  asserted; the source scan matches import specifiers, so a computed dynamic
  import would evade it.
- **File paths reach the model.** If a path is itself sensitive, do not give
  this server the root it sits in.
- **Windows is untested.** No POSIX-only API is used and paths go through
  `node:path`, but nobody has run it there, and the cross-device tests run only
  on macOS.

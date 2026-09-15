# @shieldfive/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets an
AI assistant manage files on your own machine: find duplicates by content, find
what is large or stale, and move, rename or trash them.

It holds no ShieldFive credential, makes no network request, and does not import
`@shieldfive/crypto`. Those are not gaps to be filled in a later version. They
are the security boundary, and the section below explains what they cost you.

```sh
npx @shieldfive/mcp ~/Documents ~/Downloads
```

## Install

Requires Node 20 or newer.

```sh
npm install -g @shieldfive/mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shieldfive": {
      "command": "npx",
      "args": ["-y", "@shieldfive/mcp", "/Users/you/Documents", "/Volumes/Archive"]
    }
  }
}
```

Every path after the package name is a **root**. The server can read and write
inside those directories and nowhere else. There is no default root and no
override flag — a server started with no roots will refuse every call and tell
you so.

`SHIELDFIVE_MCP_ROOTS` adds roots as well — the two are combined, not
alternatives — as a list separated by your platform's path separator (`:` on
macOS and Linux, `;` on Windows):

```sh
SHIELDFIVE_MCP_ROOTS="/Users/you/Documents:/Volumes/Archive" npx @shieldfive/mcp
```

## What this cannot do

**It cannot see your ShieldFive vault.** Not the file list, not the names, not
the sizes. It will not tell you whether a local file is already backed up,
because it has no way to know and it is not permitted to guess.

That is a deliberate trade. The alternative was to authenticate with a full
ShieldFive account JWT — the only credential the vault API accepts. That token
also opens `/api/vault-key`, which returns your wrapped root key and an ML-KEM
public key, and every content-download route, and **none of it can be scoped
away**, because no scoped vault credential exists. A server holding that token
would be *declining* to read your files rather than being *unable* to, with the
difference resting on a client-side denylist and on nothing else on your machine
reading the token file. A server holding no token cannot read them at all.

When a scoped, metadata-only key exists, vault tools can be added behind it.
Until then this is a local file manager that happens to be published by the
people who make an encrypted vault.

**It will never infer that two files are the same from their names and sizes.**
Duplicate detection reads both files and compares a full SHA-256 of their
contents. Name matching is how a deduplication tool deletes the only copy of
something, and the cost of getting it right is a few seconds of disk I/O.

Hashing is budgeted, though, and the budget can make the answer incomplete.
Candidates are bucketed by size, screened on a hash of the first 64 KiB where
the files are bigger than that, then confirmed with a full digest. Every read of
either kind counts against `max_files_hashed`, 20,000 by default. When the
budget runs out, whole same-size groups go unhashed and the result says how many
and how much they could have been worth. Groups are processed largest-first, so
what survives a tight budget is what was worth the most.

**It deletes nothing.** `trash_local` *moves* files into a
`.shieldfive-mcp-trash` directory inside the root they came from, and writes a
`manifest.json` recording where each one was. **No disk space is freed** until
you delete that directory yourself, in your own file manager, with your own
undo. The tool says so in its own output so the assistant cannot report the
space as reclaimed.

That holds for overwriting too. `move_local` with `overwrite: true` moves the
item already at the destination into the trash and then takes its place; it does
not remove it. The preview tells you how many files and how many bytes would be
displaced, not just how many are being moved.

**Every tool that changes anything does nothing by default.** Call it without
`confirm: true` and it resolves the paths, checks containment, reports exactly
what it would do, and stops. The preview runs the same code as the action, so a
plan that reports a refusal is a refusal.

## Tools

| Tool | Reads | Writes |
|---|---|---|
| `list_local` | files, sizes, dates | — |
| `find_duplicates` | file contents (SHA-256) | — |
| `find_large_files` | sizes | — |
| `find_old_files` | modification times | — |
| `storage_summary` | sizes, by extension and directory | — |
| `move_local` | sizes of both the source and anything it would displace | moves a file or folder; moves a displaced destination to the trash |
| `rename_local` | — | renames in place |
| `create_local_folder` | — | creates a directory |
| `trash_local` | sizes of the subtree being trashed | moves into the trash directory, writes a manifest |

Defaults, all overridable per call: `list_local` returns 200 rows, the other
listings 100. `find_large_files` starts at `min_bytes` 100,000,000 (100 MB).
`find_old_files` at `older_than_days` 365. `find_duplicates` skips empty files
(`min_bytes` 1), hashes at most `max_files_hashed` 20,000 of them and returns
100 groups, each listing at most 50 of its copies. `storage_summary` reports the
top 15 extensions and top 15 directories. Every scan stops at `max_files`
200,000 across all roots and 64 directory levels.

`find_old_files` reports modification time, which is a weak signal: some copy
operations reset it to the copy date, and an untouched file is not an unwanted
one. The tool says this in its own result rather than leaving the assistant to
present a shortlist as a verdict.

### The walk is not exhaustive

Every read tool walks the same way, and it skips things by default:

- **Hidden entries**, unless you pass `include_hidden: true`.
- **Nineteen build and cache directories** by name, wherever they appear:
  `node_modules`, `.git`, `.svn`, `.hg`, `.cache`, `.venv`, `venv`,
  `__pycache__`, `.next`, `.turbo`, `dist`, `build`, `target`, `Pods`,
  `.gradle`, `.tox`, `.mypy_cache`, `.pytest_cache`, and this server's own
  trash. `build`, `dist` and `target` are ordinary folder names outside a code
  tree, so this can exclude real data — there is no way to override the list
  yet.
- **Symlinks**, always, with no override.

All three are counted and reported in the result's warnings, so a total that
looks too small says why. It still means `storage_summary` is not a disk-usage
tool: point it at a developer's home directory and it will tell you so, but it
will not tell you where the space went.

### Emptying the trash

This server does not, and cannot. `trash_local` moves files into
`<root>/.shieldfive-mcp-trash/<timestamp>/` and writes a `manifest.json` beside
them; removing them for real is a `rm -rf` you run yourself, once you have
looked at what is in there. Nothing here frees disk space on its own.

## How containment works

Every path an assistant supplies is resolved with `realpath` — following every
symlink — before anything touches it, and the result must sit inside a
configured root. A separator-aware boundary check means `/data/roots-evil` does
not match the root `/data/root`.

That ordering is the point. A string check on the supplied path is defeated by
`..`; a check after `path.resolve` is still defeated by a symlink, because
`/allowed/link -> /etc` resolves to a string under `/allowed` while reading
`/etc`. Resolving links first closes both, and it is why the directory walk uses
`lstat` and never follows a link — a link the walk traversed would be a path
containment never got to see.

Destinations that do not exist yet — a move target, a new folder — are checked
by resolving the nearest existing ancestor and re-appending the rest, so writing
through a symlinked parent is caught before the write rather than after it.

## What the tests assert

`npm test` runs 99 tests. The ones worth knowing about:

- A symlink pointing out of a root is refused, on both the read and the write
  side.
- Two files with the same name and the same size but different contents are
  **not** reported as duplicates.
- `trash_local` leaves the bytes readable at their new location and reports
  `space_freed_bytes: 0`.
- No file under `src/` imports a networking module, calls `fetch`, spawns a
  subprocess, or reads any environment variable other than
  `SHIELDFIVE_MCP_ROOTS`.
- A real MCP client over a real stdio transport sees nine tools and no vault
  tool, including when the server is started through a symlink the way npm
  installs it.

The network assertion has a limit worth stating: it proves nothing in `src/`
reaches the network. It does not prove the dependency tree is network-free —
`@modelcontextprotocol/sdk` ships HTTP transports for other people's servers,
and claiming otherwise would be false. What closes that gap is that `server.mjs`
imports the stdio transport and no HTTP one, which is also asserted.

## Limits

- **Sizes are file-content sizes.** They exclude directory overhead and ignore
  filesystem compression, sparse files and APFS clones, so totals will not match
  a disk utility exactly.
- **Scans are capped** at 200,000 files and 64 directory levels by default. When
  a cap is hit the result says so, in the summary line as well as in a field:
  a scan that stopped at a cap otherwise reads exactly like one that finished,
  and the assistant reports a partial list as the whole of it.
- **Windows is untested.** The code uses no POSIX-only API, and path handling
  goes through `node:path`, but nobody has run it there.

[SECURITY.md](SECURITY.md) carries the rest: time-of-check/time-of-use,
hardlinks, what inheriting the environment does and does not mean, and what the
no-network assertion covers.

## Security

Report vulnerabilities to `security@shieldfive.com`. See
[SECURITY.md](SECURITY.md).

## Licence

Apache-2.0.

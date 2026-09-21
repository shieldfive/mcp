# @shieldfive/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets
Claude, ChatGPT, Cursor or a local model tidy two things:

- **your ShieldFive vault**: find duplicates, see what takes the space, rename,
  move, and move to the Bin. It works on the folders you grant, decrypts on your
  machine, and every change can be undone;
- **folders on your own disk**: the same jobs, with no network access at all.

ShieldFive's servers never see a file name or a byte of content in the clear,
and that holds with this server running too. Decryption happens inside this
process, on your computer. What the assistant then does with what it reads is a
separate question, answered under [Security model](#security-model).

<!-- DEMO: a 40-second screen recording of a duplicate-cleanup session in Claude
Desktop: "find duplicates in my Photos" → groups with sizes → "trash the copies"
→ preview → confirm → the items appear in ShieldFive's Bin → one is undone from
Settings → AI assistants. Record against a demo vault, never a real one. -->

## Connect your vault in 60 seconds

Requires Node 20 or newer.

1. Add the server to your assistant. For Claude Desktop, add this to
   `claude_desktop_config.json` (Cursor uses the same block in `~/.cursor/mcp.json`):

   ```json
   {
     "mcpServers": {
       "shieldfive": { "command": "npx", "args": ["-y", "@shieldfive/mcp"] }
     }
   }
   ```

   For Claude Code: `claude mcp add shieldfive -- npx -y @shieldfive/mcp`

2. Restart the assistant and ask it to *tidy up my ShieldFive vault*. It calls
   `vault_connect`, which opens ShieldFive in your browser.
3. In that tab, choose the folders, *Read only* or *Read and organize*, and an
   expiry (1 hour to 90 days), then click **Authorize**.

That is the whole setup: the connection is delivered straight to the server
running on your computer — over `127.0.0.1`, never through ShieldFive — and
stored in your system keychain. Nothing is copied by hand.

To connect before you start a conversation, run `npx -y @shieldfive/mcp login`:
same browser page, same result. `login --paste` takes a connection string you
copied from Settings → AI assistants instead, for a machine with no browser.

`npx @shieldfive/mcp status` shows which connection is configured and whether
ShieldFive still accepts it. `npx @shieldfive/mcp logout` removes it from the
keychain. Revoking it in ShieldFive is what cuts off access everywhere.

For CI or a machine without a keychain, set `SHIELDFIVE_GRANT` to the connection
string instead. Anything that can read the server's environment can then read
the connection, so prefer the keychain wherever there is one. Setting
`SHIELDFIVE_GRANT=none` keeps one client local-only on a machine whose keychain
holds a connection for another.

### How the browser hand-off is kept honest

- The page never accepts a callback URL, only a port number, and builds
  `http://127.0.0.1:<port>/callback` itself. A crafted link cannot send your
  connection anywhere but your own machine.
- The listener accepts exactly one delivery: a POST to `/callback`, `Host`
  exactly the loopback address (so a rebound DNS name is refused), no `Origin`
  but ShieldFive's, and a 256-bit state compared in constant time. Then it
  closes.
- The connection string travels in a form body, never in a URL, so it does not
  land in browser history.
- The listener exists only while a connection is being authorized, and for at
  most 10 minutes.

## Security model

In plain terms:

- **The connection string holds two things.** A *token* the server checks on
  every request, and a *secret* that never leaves your machine. ShieldFive stores
  only a hash of the token and has never seen the secret.
- **The secret opens only the folders you chose.** When you create a connection,
  your browser wraps those folders' keys under a key derived from the secret. It
  wraps nothing else: not your vault root key, not your password, not your
  post-quantum secret key. Subfolders open through the vault's normal folder-key
  chain. A folder you did not choose cannot be opened with anything this server
  holds.
- **ShieldFive enforces scope, expiry and revocation on every request.** The
  checks in this process only produce clearer errors; the server is the
  boundary. Revoking a connection makes its next request fail. Nothing is
  cached that would outlive a revocation.
- **Decryption happens here, in memory.** No plaintext, key or ciphertext is
  written to disk. The vault modules do not import the filesystem, and a test
  asserts that.
- **Nothing is deleted.** `vault_trash` moves items into a folder in your Bin
  that belongs to the connection. There is no permanent-delete tool, and the
  API a connection can reach has no delete route. Every rename, move and trash
  appears in *Settings → AI assistants → Activity* with an Undo button.
- **Every change is previewed first.** Mutating tools report a plan, and the
  confirmed call must carry that plan's token and is refused if the items
  changed in between.

What this does not protect:

- **Your AI provider sees what the assistant reads.** File names, and the
  contents of files the assistant opens, go to the assistant, and for a cloud
  assistant that means to its provider, like the rest of your conversation. The
  only way to avoid that is a local model.
- **Revoking cannot un-read.** Anything the assistant has already read stays
  read. Nothing else survives it: file contents are streamed through
  ShieldFive on each request, so there is no download link to outlive a
  revocation.
- **A connection is built from what the server shows your browser when you
  create it.** Every later extension is checked against your own keys, so a
  compromised server cannot widen a connection afterwards. At the moment of
  creation, though, a compromised server could mislabel which folder you
  picked.
- **A copied connection string is a live key** to the folders it covers until
  it expires or you revoke it. Keep it in the keychain.
- **Files can contain instructions aimed at the assistant.** This server marks
  every name and file content as data, fences file contents in a block the file
  cannot close, caps `vault_trash` at 50 items per call, requires a preview for
  every change, and keeps every change undoable. A model can still be talked
  into a reversible mistake inside the folders you granted.

The full design, including the threat model and the reasoning behind each
decision, is in
[`docs/mcp-grants-design.md`](https://github.com/shieldfive/web/blob/main/docs/mcp-grants-design.md).

## Vault tools

`vault_connect` is always available. The rest are registered once a connection
exists — connecting mid-conversation announces them with
`notifications/tools/list_changed`. Everything below names things by id; paths
are for people.

| Tool | Needs | What it does |
|---|---|---|
| `vault_connect` | — | opens ShieldFive in the browser to authorize a connection, and stores it in the keychain |
| `vault_list_files` | read | files and folders in scope, with decrypted names, paths, sizes, dates |
| `vault_search_files` | read | by name, path, extension, size or date, run locally over decrypted names |
| `vault_storage_stats` | read | totals, the biggest folders and files, a breakdown by type |
| `vault_find_duplicates` | read | same-size files decrypted in memory and compared by SHA-256; budgeted, and says when a result is a lower bound |
| `vault_read_file` | read | text files as fenced, untrusted content (up to 1 M characters); other types return details only |
| `vault_rename` | organize | rename a file or folder |
| `vault_move` | organize | move into another folder in scope |
| `vault_create_folder` | organize | create a folder in scope |
| `vault_upload` | write | encrypt a local file here and put it in the vault, then read it back and compare before you are told it is safe to remove the original |
| `vault_trash` | organize | up to 50 items into the connection's folder in the Bin |

Limits a user may meet:

- **Post-quantum files uploaded from a phone or the CLI** show as
  `readable: false` until you next open ShieldFive on the web, which adds the key
  the connection needs. Files uploaded in the web app are ready straight away.
- **The first listing of a large vault takes a while.** Each name costs about
  70 ms of Argon2id, spread over your CPU cores (about 20 seconds for 2,000
  names on 8 cores). Names are cached in memory for the rest of the session.
- **Items at the very top of a whole-vault connection** can be read and moved
  into a folder, but not renamed in place, and nothing can be moved to the top.
  Their names are sealed under your vault root key, which a connection never
  holds.
- **Uploads are not available yet.** The design allows them, but they ship
  after the read and organize tools have been in use for a while.

## Local files

Every path after the package name is a **root**. The local tools can read and
write inside those directories and nowhere else, and make no network request.

```sh
npx @shieldfive/mcp ~/Documents ~/Downloads
```

In `claude_desktop_config.json`:

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

With a connection configured and no roots, only the vault tools are registered.
With roots and no connection, only the local tools are, and the server behaves
exactly as 0.2.0 did. With both, you get both.

`SHIELDFIVE_MCP_ROOTS` adds roots as well — the two are combined, not
alternatives — as a list separated by your platform's path separator (`:` on
macOS and Linux, `;` on Windows):

```sh
SHIELDFIVE_MCP_ROOTS="/Users/you/Documents:/Volumes/Archive" npx @shieldfive/mcp
```

Whitespace around a root is ignored. In a path given to a tool it is not: there,
every character is part of the path.

### See it work first

```bash
npm run demo
```

`demo/run-demo.mjs` builds five files in a temporary directory — two with
identical contents under different names, a same-size decoy, a 12 MB archive and
a two-year-old PDF — runs the read tools over them, previews a trash call, then
confirms it and shows the manifest. It touches nothing outside that directory
and removes it at the end (`--keep` leaves it in place).

## What the local tools cannot do

**They cannot tell you whether a local file is already in your vault.** Matching
a local name and size against a vault listing is how a tool deletes the only
copy of something, and this server will not guess.

**They cannot stop the results from reaching your AI provider.** The local
tools make no network request, and that is worth exactly what it says and no
more:
everything they return — paths, file names, sizes, dates, the digests they
report — goes back to the AI client that called it, and if that client is a
cloud assistant, those names travel to the assistant's provider like the rest
of your conversation. Choose roots on that basis.

**It will never infer that two files are the same from their names and sizes.**
Duplicate detection reads both files and compares a full SHA-256 of their
contents. Name matching is how a deduplication tool deletes the only copy of
something, and the cost of getting it right is a few seconds of disk I/O.

Hashing is budgeted, though, and the budget can make the answer incomplete.
Candidates are bucketed by size, screened on a hash of the first 64 KiB where
the files are bigger than that, then confirmed with a full digest. Every read of
either kind counts against `max_files_hashed`, 20,000 by default. When the
budget runs out, the rest goes unhashed — the group it runs out in is hashed in
part, oldest copies first — and the result says how many files and how much space
were never checked. Groups are processed largest-first, so what survives a tight
budget is what was worth the most.

What counts as reclaimable is counted per file on disk. Names that are hardlinks
to one file are one copy, because removing one of them frees nothing. APFS clones
— what Finder's Duplicate makes on an APFS volume — share their storage too, but
nothing this server can read tells a clone from a real copy, so clones are
reported as reclaimable when trashing one frees little or nothing. The copy
nominated to keep is the one modified earliest; a tie goes to the shorter path,
then to the path in code-unit order, so the same tree always nominates the same
copy.

**It deletes nothing of yours, with one exception.** `trash_local` *moves* files
into a `.shieldfive-mcp-trash` directory on the same volume they are on, and
writes a `manifest.json` recording where each one was. **No disk space is freed**
until you delete that directory yourself, in your own file manager, with your
own undo. The tool says so in its own output so the assistant cannot report the
space as reclaimed. The exception is a `move_local` between volumes, which has
to copy: its source is removed, but only after the copy has been verified — see
[Moving across volumes](#moving-across-volumes).

That holds for overwriting too. `move_local` with `overwrite: true` moves the
item already at the destination into the trash and then takes its place; it does
not remove it. The preview tells you how many files and how many bytes would be
displaced, not just how many are being moved. If the move then fails, the
displaced item is put back.

**Every tool that changes anything does nothing by default.** Call it without
`confirm: true` and it resolves the paths, checks containment, reports exactly
what it would do, and stops. The preview runs the same checks as the action, so
a plan that reports a refusal is a refusal.

**And a confirmed call has to be the plan you saw.** The preview returns a
`plan_token`; `confirm: true` without it is refused. The confirmed call plans
again from the filesystem as it is now, compares that plan with the one the
token approved — the paths, what each entry is, its size and modification time,
and the file and byte counts underneath it — and refuses if anything differs,
naming what changed. A token performs one change and expires after ten minutes.
So a directory that grew, a destination that appeared, or a path that now points
at a different file stops the call instead of silently widening it.

## Local tools

| Tool | Reads | Writes |
|---|---|---|
| `list_local` | files, sizes, dates | — |
| `find_duplicates` | file contents (SHA-256) | — |
| `find_large_files` | sizes | — |
| `find_old_files` | modification times | — |
| `storage_summary` | sizes, by extension and directory | — |
| `move_local` | sizes of both the source and anything it would displace | moves a file, folder or symlink; moves a displaced destination to the trash; between volumes, copies, verifies, then removes the source |
| `rename_local` | — | renames in place, never over an existing name |
| `create_local_folder` | — | creates a directory |
| `trash_local` | sizes of the subtree being trashed | moves into the trash directory on the item's own volume, writes a manifest |

Defaults, all overridable per call: `list_local` returns 200 rows, the other
listings 100. `find_large_files` starts at `min_bytes` 100,000,000 (100 MB).
`find_old_files` at `older_than_days` 365. `find_duplicates` skips empty files
(`min_bytes` 1), hashes at most `max_files_hashed` 20,000 of them and returns
100 groups, each listing at most 50 of its copies. `storage_summary` reports the
top 15 extensions and top 15 directories. Every scan stops at `max_files`
200,000 files across all roots, and walks the root and 64 levels of
subdirectories below it.

Every override has a ceiling, enforced by the MCP schema and again by the tool
itself: `limit` 10,000 rows, `max_files` 1,000,000, `max_files_hashed`
1,000,000, `paths` 1,000 per `trash_local` call, 4,096 characters for a path and
255 bytes for `new_name`. A refusal quotes only the start of a value that was
too long.

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

When the `max_files` budget runs out before every root has been walked, the
result lists the roots it walked under `scanned` and the others under
`not_scanned`, and its warning names them.

### Emptying the trash

This server does not, and cannot. `trash_local` moves each item into
`.shieldfive-mcp-trash/<batch>/` in the highest directory, between the item and
its root, that is on the item's own volume: the root itself, unless the item is
on a drive mounted inside the root, and then that drive's top directory.
`<batch>` is a timestamp, a process id and a counter, so no two calls share one.
The `manifest.json` beside the items is written before any of them moves and
lists where each came from; an entry whose `trashed_to` does not exist was
planned but not moved. Removing them for real is a `rm -rf` you run yourself,
once you have looked at what is in there. Nothing here frees disk space on its
own.

A mount point cannot be trashed, because no directory on its own volume inside
the root can hold it. If `.shieldfive-mcp-trash` is a symlink or a file,
`trash_local` and an overwriting `move_local` refuse rather than follow it.

### Moving across volumes

`rename(2)` cannot cross volumes, so a move between them is a copy followed by
removing the source — the one place this server removes something you made. It
is done so that a failure at any point loses nothing:

- The copy is made under a fresh hidden name beside the destination
  (`.shieldfive-mcp-incoming-<pid>-<n>`), created exclusively, and put in place
  without replacing anything. Nothing that was already there is touched.
- A folder holding a symlink, a FIFO, a socket or a device file is refused
  before any of it is removed, because a copy cannot carry those faithfully.
- Every file is flushed to disk and compared with its source — same size, same
  SHA-256 — and the source must not have changed since it was copied. If either
  check fails, the copy is discarded and the source stays.
- The source is removed file by file, each only if it is still the file that was
  copied, and folders only once they are empty. Anything that changed or
  appeared during the move is left where it is and listed in
  `source_left_in_place`.

A crash in the middle can leave a partial copy under that hidden name. The
source is intact until its copy is in place.

### Cancellation

A cancelled request starts no change. `trash_local` stops between items, never
inside one, so each item is either moved and recorded or untouched, and the
error says which. A `move_local` cancelled before its source starts being
removed is undone, including putting back anything it displaced; after that
point it finishes, because stopping would leave half a tree on each side. The
MCP SDK sends no response to a cancelled request, so what a cancelled call did
is written to the server's stderr log and, for the trash, to the manifest.

## How containment works

Every path an assistant supplies is used exactly as given, so `"report "` is
never `"report"`, and resolved with `realpath` — following every symlink — before
anything reads it or writes through it. The result must sit inside a configured
root. A separator-aware boundary check means `/data/roots-evil` does not match
the root `/data/root`.

That ordering is the point. A string check on the supplied path is defeated by
`..`; a check after `path.resolve` is still defeated by a symlink, because
`/allowed/link -> /etc` resolves to a string under `/allowed` while reading
`/etc`. Resolving links first closes both, and it is why the directory walk uses
`lstat` and never follows a link — a link the walk traversed would be a path
containment never got to see.

Destinations that do not exist yet — a move target, a new folder — are checked
by resolving the nearest existing ancestor and re-appending the rest, so writing
through a symlinked parent is caught before the write rather than after it. A
symlink whose target does not exist is refused wherever a write would pass
through it: `realpath` reports it exactly like a missing path, and taking that
at its word would let a copy land wherever the link points.

The one thing not followed is the item a mutating tool acts on. A symlink given
to `move_local`, `rename_local` or `trash_local` is moved, renamed or trashed
itself, the way `mv` treats it, and what it points to is not touched; only the
link's own position has to be inside a root. The same goes for the destination
of a move: a symlink there, dangling or not, is an existing entry that
`overwrite: true` would move to the trash, not a folder to move into. Give the
folder's real path for that.

`rename_local` and `move_local` do not replace something that appears at the
destination after they have checked it. A file is hard-linked to its new name
and only then unlinked from the old one, a symlink is recreated, and a folder is
renamed over an empty placeholder made a moment before, so something appearing
in between makes the operation fail rather than be overwritten. Where there is
no such operation — FIFOs, sockets and device files, filesystems without hard
links such as FAT and exFAT, and folders on Windows — the tool checks and then
renames, and a file created in that instant would be replaced.

## What the tests assert

`npm test` runs 215 tests. The ones worth knowing about:

- A symlink pointing out of a root is refused, on both the read and the write
  side, and so is a dangling symlink on a write path.
- A `.shieldfive-mcp-trash` that is a symlink out of the root is refused, and
  nothing is written through it.
- Two files with the same name and the same size but different contents are
  **not** reported as duplicates, and two names for one file are not counted as
  space to reclaim.
- `trash_local` leaves the bytes readable at their new location, on the same
  volume, and reports `space_freed_bytes: 0`.
- On a RAM disk mounted inside a root, a move across volumes keeps a source
  whose copy arrives corrupt or that changes while it is copied, leaves an
  existing file at its old staging name alone, refuses a folder holding a FIFO,
  and never writes through a dangling symlink. These run on macOS and are
  skipped elsewhere.
- A file that appears at the new name between the check and the rename is not
  replaced.
- A cancelled request moves nothing, and a trash batch cancelled midway says
  exactly what it moved.
- Only `src/vault/api.mjs` calls `fetch`, and only to an https ShieldFive
  origin. No local-tool module imports anything from the vault half, and the
  only environment variables read are `SHIELDFIVE_MCP_ROOTS`,
  `SHIELDFIVE_GRANT` and `SHIELDFIVE_API_URL`.
- The browser hand-off is the one inbound socket and the one subprocess in the
  package: `src/vault/connect.mjs` binds a random port on `127.0.0.1`, opens no
  connection of its own, and launches the browser with a fixed command and no
  shell. A delivery from another origin, with another state, to another `Host`,
  by another method, or after the first one, is refused.
- The vault modules import no filesystem module, so decrypted data cannot be
  written to disk. No module uses a cipher, HMAC or KDF of its own. All
  cryptography comes from `@shieldfive/crypto`.
- Against an in-memory ShieldFive that serves real ciphertext in all three vault
  formats, over a real MCP client:
  - files decrypt through the grant's keys only, and nothing outside the scope
    is listed, read or even requested;
  - a revoked or expired connection fails the very next call;
  - renames and moves re-seal names and keys so the owner's own keys still
    open them;
  - the grant secret and token never appear in any request body or path.
- A file whose contents tell the assistant to trash everything comes back
  inside a fence it cannot close. Reading it issues only reads, and a 51-item
  trash call is refused.
- A real MCP client over a real stdio transport sees exactly the nine local
  tools when no connection is configured, including when the server is started
  through a symlink the way npm installs it.

The network assertion has a limit worth stating: it proves what `src/` does,
not what the dependency tree could do. `@modelcontextprotocol/sdk` ships HTTP
transports for other people's servers. What closes that gap is that
`server.mjs` imports the stdio transport and no HTTP one, which is also
asserted.

## Limits

- **The plan check narrows the gap between preview and action; it does not
  close it.** The comparison happens inside the confirmed call, so a change
  arriving between that check and the write itself is still possible. Each tool
  re-checks its own destination immediately before writing, which is what makes
  that window small rather than absent, and no path-based tool can do better.
- **A plan binds what it named.** For a directory, that is the entry itself plus
  the file and byte counts underneath it — enough to catch content appearing,
  disappearing or changing size, but not a file edited in place to exactly the
  same length within the same second.
- **Sizes are file-content sizes.** They exclude directory overhead and ignore
  filesystem compression, sparse files, hardlinks and APFS clones, so totals will
  not match a disk utility exactly; `storage_summary` counts every name of a
  hardlinked file.
- **APFS clones look like copies.** `find_duplicates` reports them as
  reclaimable, and trashing one frees little or nothing.
- **Scans are capped** by default at 200,000 files, and at the
  root and 64 levels of subdirectories below it. When a cap is hit the result
  says so, in the summary line as well as in a field: a scan that stopped at a
  cap otherwise reads exactly like one that finished, and the assistant reports
  a partial list as the whole of it.
- **Cross-volume behaviour is tested on macOS only,** against a RAM disk the
  tests mount inside their own temporary directory.
- **Windows is untested.** The code uses no POSIX-only API, and path handling
  goes through `node:path`, but nobody has run it there.

[SECURITY.md](SECURITY.md) carries the rest: time-of-check/time-of-use, the
windows in which a rename can still replace something, hardlinks, what
inheriting the environment does and does not mean, and what the no-network
assertion covers.

## Security

Report vulnerabilities to `security@shieldfive.com`. See
[SECURITY.md](SECURITY.md).

## Licence

Apache-2.0.

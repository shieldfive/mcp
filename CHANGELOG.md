# Changelog

All notable changes to `@shieldfive/mcp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 — 2026-09-20

Connecting a vault no longer involves copying anything. Ask the assistant to
tidy your vault, authorize it in the ShieldFive tab that opens, and carry on.

### Added

- `vault_connect`: opens ShieldFive in the user's browser, where the owner
  chooses folders, permissions and expiry as before, and receives the new
  connection over `127.0.0.1`. It is stored in the system keychain. The tool
  reports back while the owner is still deciding and picks up the result on the
  next call, because a tool call cannot wait ten minutes.
- `npx @shieldfive/mcp login` now opens that same page; `login --paste` keeps
  the old behaviour for a machine with no browser.
- `SHIELDFIVE_GRANT=none` keeps one client local-only on a machine whose
  keychain holds a connection for another.

### Changed

- The vault tools are registered as soon as a connection exists, including one
  made mid-conversation, which the server announces with
  `notifications/tools/list_changed`. Until then only `vault_connect` is
  registered: a tool that cannot work is still not offered.
- A revoked or expired connection now tells the assistant to call
  `vault_connect`, instead of sending the user to the terminal.

### Security

- The hand-off is the only inbound socket in this package and the only
  subprocess it starts. The listener binds a random loopback port, accepts one
  POST to `/callback` with the loopback `Host`, no `Origin` other than
  ShieldFive's and a 256-bit state compared in constant time, then closes. It
  opens no connection of its own, and the browser is launched with a fixed
  command and no shell.
- The ShieldFive page builds the callback address from a port number and
  accepts no callback URL, so a crafted link cannot deliver a connection
  anywhere but the machine the browser runs on. The connection string is sent
  in a form body, never in a URL, so it does not reach browser history.

## 0.3.0 — 2026-09-19

Vault tools. The server can now work on a ShieldFive vault through an **agent
grant**: a connection the user creates in ShieldFive → Settings → AI
assistants, limited to chosen folders and permissions, expiring (at most 90
days), revocable, audited, and enforced by the server on every request.

### Added

- `vault_list_files`, `vault_search_files`, `vault_storage_stats`,
  `vault_find_duplicates` and `vault_read_file` (read), and `vault_rename`,
  `vault_move`, `vault_create_folder` and `vault_trash` (organize). They are
  registered only when a connection is configured.
- `npx @shieldfive/mcp login | logout | status`. The connection string is
  stored in the OS keychain through `@napi-rs/keyring`, with `SHIELDFIVE_GRANT`
  as the fallback for headless use.
- Decryption of all three vault formats (post-quantum hybrid, AES-GCM v1 and
  legacy v0) in memory, through `@shieldfive/crypto`. Names are decrypted on a
  worker pool and cached in memory.
- Progress notifications for name decryption and duplicate hashing.
- Every vault result is marked as data rather than instructions. File contents
  are fenced with a random marker the file cannot close.

### Changed

- **The security boundary is restated, not removed.** 0.2.0 held no credential
  and made no network request. That still holds for the local tools, which
  import nothing from the vault half, so a server with no connection behaves as
  before. The vault half talks to one https origin with one scoped credential.
  `test/boundary.test.mjs` asserts the new lines: network access only in
  `vault/api.mjs`, no filesystem access in any vault module, no cipher outside
  `@shieldfive/crypto`, no account credential anywhere.
- A server started with a connection and no roots registers only the vault
  tools.

## Unreleased

## 0.2.0 - 2026-09-16

The first version published to npm. 0.1.0 below was tagged in this changelog
and never published; nothing depends on its behaviour, but its contract did
change here — a confirmed call now needs the `plan_token` its preview returned —
so the version moves a minor step rather than a patch, as semver asks of a 0.x
release that breaks callers.

Fixes from a second review before the first publish. Each item has a test that
failed before its fix.

### Security

- A confirmed call was not bound to the preview the user approved. `confirm:
  true` planned the operation again from scratch, so a directory that had grown,
  a destination that had appeared, or a path that now pointed at a different file
  was acted on without the user ever being shown it. Each preview now returns a
  `plan_token`; a confirmed call must carry it, and the tool refuses
  (`plan_changed`) when the plan it builds differs from the one approved, naming
  what changed. Tokens are single use and expire after ten minutes.
- The trash directory was never resolved or `lstat`'d. With
  `<root>/.shieldfive-mcp-trash` a symlink out of the root, `trash_local` and an
  overwriting `move_local` moved the user's files and the manifest out of the
  root. The directory is now checked while planning, created without following
  links and checked again before anything moves in; a link or a non-directory
  there is refused (`trash_unsafe`).
- A dangling symlink read as a free path. A move onto one previewed
  `replaces_existing: false`; on the same device the link was replaced with no
  trash entry, and across devices the copy wrote through it, outside the root,
  before removing the source. At a destination it is now an existing entry, and
  anywhere a write would pass through it the write is refused
  (`dangling_symlink`).
- The cross-device move fallback deleted data. It `rm -rf`'d whatever was at
  `<destination>.shieldfive-mcp-incoming`, dropped FIFOs, sockets and device
  files and then removed the source tree, and removed a file's source without
  flushing or checking the copy. A cross-device move now copies under a fresh,
  exclusively created name, refuses symlinks and special files in the tree
  (`symlink_in_tree`, `special_file_in_tree`), flushes and verifies every file by
  size and SHA-256 against a source that has not changed
  (`copy_verification_failed`, `source_changed`), and removes the source entry by
  entry, only what is unchanged since it was copied (`source_left_in_place`).
- The trash lived per root rather than per volume, so for a root such as
  `/Volumes`, trashing from an external drive copied the tree onto the boot
  volume. An item's trash is now on its own volume, in the highest directory
  between it and its root on that device; a move into the trash is always a
  rename; a mount point cannot be trashed (`trash_no_same_volume`).
- `trash_local` on a symlink trashed the tree it pointed to, and `rename_local`
  renamed the file behind a link. `move_local`, `rename_local` and `trash_local`
  now act on a link itself, never on its target.
- `rename_local`'s "never replaces" was a check followed by `rename(2)`. Renames
  and moves now use operations that fail when the destination exists: a hard link
  then an unlink for files, a recreated symlink, a rename over an empty
  placeholder for directories. Special files, filesystems without hard links and
  directories on Windows still fall back to checking and then renaming;
  SECURITY.md records the window that leaves.

### Fixed

- `find_duplicates` spent its hashing budget all-or-nothing per size group, so
  the most valuable group was skipped when its worst case did not fit and the
  smaller groups behind it were hashed instead. The budget is now spent per file,
  largest group first, hashing a group in part when it must
  (`groups_partially_hashed`, `files_not_hashed`).
- The copy nominated to keep was chosen by modification time, with ties left to
  directory order. A tie now goes to the shorter path, then to the path in
  code-unit order (`compareKeeper`).
- Hardlinks counted as reclaimable space. Names of one file are now one copy,
  listed under `hardlinked_names`, and `reclaimable_bytes` counts files on disk.
- A trash batch that failed after moving something could report the moved item
  as recorded "in no manifest (nothing moved)", and the structured detail never
  reached the client. The error now names each moved item and its manifest, and
  the detail is returned as a second content block.
- Manifest updates raced: concurrent calls in the same millisecond shared a batch
  and lost entries, and a corrupt manifest was silently reset. Each call now has
  its own exclusively created batch directory; its manifest is written before
  anything moves, atomically and one write at a time, and no manifest this
  server did not write is read or replaced.
- Path arguments and `new_name` were trimmed, so `"report "` acted on
  `"report"`. They are used exactly as given.
- `limit`, `max_files`, `max_files_hashed`, `paths` and `new_name` had no upper
  bound, and a refusal echoed its input whole. They are capped — 10,000 rows;
  1,000,000 files; 1,000,000 hash reads; 1,000 paths; 255 bytes — at the MCP
  schema and again in the handlers, and echoed values are cut short.
- `trash_local` counted a path given twice twice, and given a folder and
  something inside it, moved the folder and then failed on the file. A repeated
  path is taken once and an overlap is refused before anything moves
  (`overlapping_paths`).
- The mutating tools ignored cancellation. Nothing starts once a request is
  cancelled (`cancelled`); a trash batch stops between items
  (`cancelled_partially_applied`); a move is rolled back until its source starts
  being removed. The SDK sends no response to a cancelled request, so the server
  logs what happened.
- `scanned` listed roots the file budget never reached. Payloads carry
  `scanned` and `not_scanned`, and the warning names the roots never reached.

### Changed

- A symlink given as the destination of `move_local` is an entry that
  `overwrite` can replace, not a directory to move into. Give the real path of a
  directory to move into it.
- The server version is read from `package.json` rather than kept as a second
  copy.
- The README said scans stop at "64 directory levels"; they walk the root and
  64 levels of subdirectories below it.
- Removed a scratch script committed at the repository root, a `.npmrc` and
  `.gitignore` entries left over from other projects, and renamed a test whose
  name contradicted its assertion.

### Not covered

- The cross-device tests need a RAM disk and run only on macOS; elsewhere they
  are skipped, visibly. Windows remains untested.

## 0.1.0 - 2026-09-14

Initial release.

### Added

- Nine local file-management tools over MCP stdio: `list_local`,
  `find_duplicates`, `find_large_files`, `find_old_files`, `storage_summary`,
  `move_local`, `rename_local`, `create_local_folder`, `trash_local`.
- Root-based containment. Every path is `realpath`-resolved, following symlinks,
  and must land inside a directory the user named at startup. No default root,
  no override.
- Content-based duplicate detection: grouped by size, then by a hash of the
  first 64 KiB, then confirmed by a full SHA-256. Filenames are never used to
  decide identity.
- `confirm: true` gating on every tool that changes the filesystem. Without it,
  each returns the plan its real code path produced and changes nothing.
- `trash_local` moves rather than deletes, into a `.shieldfive-mcp-trash`
  directory inside the item's own root, with a `manifest.json` recording the
  original location.

### Security

- Path containment was attacked across four independent lenses before release.
  Two data-loss paths in `move_local` were found and closed: an overwriting move
  called `rm(destination, {recursive: true, force: true})`, which destroyed every
  file under an overwritten directory while the README claimed the server deletes
  nothing; and a directory moved onto its own parent resolved its final path to
  the source itself, so the same branch deleted the source outright. Overwriting
  now moves the displaced item to the trash, and the self-move case is refused.
- `walkRoots` threw `RangeError` on any root over roughly 125,000 files — below
  the 200,000-file cap the schema advertises — because it spread the per-root
  array into `push()`. It appends in a loop, and `max_files` is now a budget
  across all roots rather than per root.
- The hidden-entry check ran on the dirent before `lstat`, so a dot-named symlink
  was counted as hidden and never reached the symlink branch.
- Files with a link count above one are counted and reported in scan warnings.
  `realpath` resolves symlinks but not hardlinks, so containment cannot see a
  second name for the same inode outside the roots.
- Request cancellation is plumbed through to the walk and to hashing. A cancelled
  scan previously ran to completion.
- A cross-device directory move is transactional. It stages the copy beside the
  target and renames it into place only once the whole tree has landed, so a
  failure mid-walk leaves the source untouched and nothing at the destination.
  Previously an interleaved copy+remove tore the source in half while the
  already-removed destination was gone for good. A move that would both displace
  an existing destination and carry a symlink in its tree is now refused before
  anything is displaced, and if the replacement fails after a displacement the
  displaced item is put back.
- Path arguments are capped at 4096 characters. An oversized path was reflected
  verbatim into the error message and into the model's context.

### Notes

- **This version cannot see a ShieldFive vault.** The vault API accepts only a
  full account JWT, which also opens the wrapped-root-key route and every
  content download, and cannot be scoped down. Holding one would make the
  content boundary a matter of restraint instead of capability. Vault tools wait
  for a scoped, metadata-only key. The reasoning is set out in
  `docs/mcp-v1-step0-discovery.md` in `shieldfive/web`.
- No network module is imported, `fetch` is never called, no subprocess is
  spawned, and `SHIELDFIVE_MCP_ROOTS` is the only environment variable read.
  Each of those is asserted by a test rather than only claimed here. The
  assertion covers this package's source, not its dependency tree, and
  SECURITY.md says so.
- Reporting was corrected in several places where a result was quietly
  incomplete: `storage_summary` omitted hidden files and build directories from
  its totals with no warning at all; `find_old_files` was the one tool that kept
  its warnings out of the summary line; the duplicate-hashing budget counted only
  the 64 KiB head pass, leaving the whole-file pass unbounded, and abandoned
  entire same-size groups when they did not fit — biased against the groups worth
  the most, since a group is large precisely because it has many copies.
- `formatBytes` promoted units before rounding, so 999,999 bytes rendered as
  "1000 KB".
- `storage_summary` credited each file only to its immediate parent, so a large
  tree split across subfolders never appeared in `largest_directories`.
- Windows is untested. The code uses no POSIX-only API and paths go through
  `node:path`, but nobody has run it there.

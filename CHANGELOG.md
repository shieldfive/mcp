# Changelog

All notable changes to `@shieldfive/mcp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Files with a link count above one are counted and surfaced. `realpath` resolves
  symlinks but not hardlinks, so containment cannot see a second name outside the
  roots; reporting it is the honest response.
- Request cancellation is plumbed through to the walk and to hashing. A cancelled
  scan previously ran to completion.
- Path arguments are capped at 4096 characters. An oversized path was reflected
  verbatim into the error message and into the model's context.

### Notes

- **This version cannot see a ShieldFive vault**, and that is the design rather
  than an omission. The vault API accepts only a full account JWT, which also
  opens the wrapped-root-key route and every content download and cannot be
  scoped down. Holding one would make the content boundary a matter of restraint
  instead of capability. Vault tools wait for a scoped, metadata-only key.
  The reasoning is set out in `docs/mcp-v1-step0-discovery.md` in
  `shieldfive/web`.
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

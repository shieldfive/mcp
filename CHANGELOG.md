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
  Each of those is asserted by a test rather than only claimed here.
- Windows is untested. The code uses no POSIX-only API and paths go through
  `node:path`, but nobody has run it there.

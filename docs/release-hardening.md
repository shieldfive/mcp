# Release hardening: admin steps

`release.yml` publishes from a job that runs in the `npm-publish` GitHub
environment. The workflow cannot protect that environment or the tags itself;
an org/repo admin does it once. Until then the `publish` job still runs (GitHub
creates an unprotected environment on first use), so do this before the next
tag.

As of 2026-10-12 `shieldfive/mcp` has no environments and no rulesets.

## 1. Protected environment `npm-publish`

UI: github.com/shieldfive/mcp → Settings → Environments → New environment →
name `npm-publish` → Configure:

- **Required reviewers**: add `chogarcia`. Leave "Prevent self-review" OFF
  while you are the only maintainer (otherwise nobody can approve your own tag).
- **Wait timer**: 0.
- **Deployment branches and tags**: "Selected branches and tags" → Add rule →
  type **Tag** → pattern `v*`. Remove any branch rule.
- **Allow administrators to bypass**: OFF.
- No environment secrets are needed (trusted publishing, no token).

Same thing from a terminal:

```sh
gh api -X PUT repos/shieldfive/mcp/environments/npm-publish --input - <<'JSON'
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [{ "type": "User", "id": REPLACE_WITH_ID }],
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON
gh api -X POST repos/shieldfive/mcp/environments/npm-publish/deployment-branch-policies \
  -f name='v*' -f type=tag
```

`REPLACE_WITH_ID` is the number from `gh api users/chogarcia -q .id`.

Each release then pauses at `publish` until you click **Review deployments →
Approve** on the run page.

## 2. Tag ruleset (who can create `v*` tags)

UI: Settings → Rules → Rulesets → New ruleset → **New tag ruleset**:

- Name `release-tags`, Enforcement **Active**.
- Bypass list: **Repository admin** role (always allow). Nobody else.
- Target tags: Include by pattern `v*`.
- Rules: **Restrict creations**, **Restrict updates**, **Restrict deletions**,
  **Block force pushes**.

Terminal equivalent:

```sh
gh api -X POST repos/shieldfive/mcp/rulesets --input - <<'JSON'
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }],
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
JSON
```

(`actor_id` 5 is the built-in Repository admin role.)

## 3. Optional: pin the environment on npm

npmjs.com → `@shieldfive/mcp` → Settings → Trusted Publisher → edit the GitHub
Actions entry (`shieldfive/mcp`, workflow `release.yml`) and set
**Environment name** to `npm-publish`. npm then refuses an OIDC publish from
any other job, even one in `release.yml`. Do this after step 1, or the next
release fails.

## Check

Push the next release tag as usual. The run should show three jobs; `publish`
waits for approval, and its log shows `npm publish dist/shieldfive-mcp-X.Y.Z.tgz`
with a provenance statement.

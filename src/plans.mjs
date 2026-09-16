// Binding a confirmed call to the preview the user approved.
//
// Every mutating tool plans twice: once for the preview, and again when it is
// called back with confirm: true. Until now the two plans were unrelated. The
// user saw "12 files, 4.1 GB" in the preview, said yes, and the confirmed call
// went out and planned again from scratch — against whatever the tree looked
// like by then. If a directory had grown, or a destination had appeared, or the
// file behind a path had been replaced, the call did something the user had
// never been shown. The pre-publish review recorded this as D3, and README,
// SECURITY.md and the CHANGELOG all said it was not covered.
//
// The fix is the usual two-phase shape. A preview registers a fingerprint of
// what it planned and hands back an opaque `plan_token`. A confirmed call must
// carry that token; the tool re-plans as before, fingerprints the result the
// same way, and refuses if the two differ — naming what changed, so the model
// can show the user a new plan rather than guess.
//
// Three properties matter:
//
//   1. The token is issued by the server and means nothing outside it. It is
//      random, not a hash of the plan, so nothing a client can compute
//      authorizes a change.
//   2. It is single use. One approval performs one change; a token cannot be
//      replayed against a tree that has moved on.
//   3. It expires. An approval from an hour ago is not consent to act on a
//      directory nobody has looked at since.
//
// What this does NOT do is close the time-of-check/time-of-use window: the
// fingerprint is taken during the confirmed call, and the filesystem can still
// change between that and the write itself. The per-tool checks immediately
// before each write are what narrow that gap, and SECURITY.md states the limit.

import { randomUUID } from 'node:crypto'

import { quote } from './format.mjs'
import { ToolError } from './roots.mjs'

/** How long an approved plan stays good for. */
export const PLAN_TTL_MS = 10 * 60 * 1000

/** How many plans are remembered at once. Oldest first out. */
export const PLAN_CAPACITY = 64

/**
 * The identity of a filesystem entry, as far as a plan is concerned.
 *
 * Device and inode say it is the same entry rather than the same path — a path
 * swapped for another file between the preview and the confirmation is a
 * different plan even when every visible field matches. Size and mtime catch a
 * file rewritten in place, where the inode does not change.
 */
export function entryId(stats) {
  if (!stats) return 'absent'
  const kind = stats.isSymbolicLink()
    ? 'symlink'
    : stats.isDirectory()
      ? 'directory'
      : stats.isFile()
        ? 'file'
        : 'special'
  return `${kind}:${stats.dev}:${stats.ino}:${stats.mtimeMs}:${stats.size}`
}

/** Stable JSON: object keys in a fixed order, so two equal plans stringify alike. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`
  }
  return JSON.stringify(value ?? null)
}

/**
 * A store of approved plans.
 *
 * In memory and per process on purpose: a plan is an approval inside one
 * conversation, and a server that has restarted has no conversation to honour
 * it in.
 */
export function createPlanStore({ now = () => Date.now(), ttlMs = PLAN_TTL_MS, capacity = PLAN_CAPACITY } = {}) {
  const plans = new Map()

  // Map iterates in insertion order, so the first key is always the oldest.
  function sweep(at) {
    for (const [token, plan] of plans) {
      if (at - plan.issuedAt >= ttlMs) plans.delete(token)
    }
    while (plans.size > capacity) plans.delete(plans.keys().next().value)
  }

  return {
    /** Register what a preview planned; returns the token that approves it. */
    issue(fingerprint) {
      const at = now()
      const token = `plan_${randomUUID().replace(/-/g, '')}`
      plans.set(token, { body: canonical(fingerprint), issuedAt: at })
      sweep(at)
      return token
    },

    /**
     * Consume a token.
     *
     * Returns the approved body, or a reason it cannot be used. Consuming
     * happens whether or not the body matches: a token that has been answered
     * once is spent, and a mismatch means the caller has to look at a new plan
     * anyway.
     */
    take(token) {
      const plan = plans.get(token)
      if (!plan) return { ok: false, reason: 'unknown' }
      plans.delete(token)
      if (now() - plan.issuedAt >= ttlMs) return { ok: false, reason: 'expired' }
      return { ok: true, body: plan.body }
    },

    get size() {
      return plans.size
    },
  }
}

/** Which fields differ between the plan that was approved and the one now. */
function differences(approved, fresh) {
  let a
  try {
    a = JSON.parse(approved)
  } catch {
    return ['the plan']
  }
  const b = JSON.parse(canonical(fresh))
  const out = []
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const before = canonical(a[key])
    const after = canonical(b[key])
    if (before !== after) out.push(key)
  }
  return out.length ? out : ['the plan']
}

/**
 * Refuse a confirmed call that is not the plan the user approved.
 *
 * Called before anything is written, and after the tool has re-planned, so the
 * comparison is between two plans built the same way from two readings of the
 * filesystem.
 */
export function requireApprovedPlan(ctx, token, fingerprint) {
  const store = ctx.plans
  if (!store) {
    throw new ToolError(
      'plan_store_missing',
      'Refused: this server has no plan store, so a confirmed call cannot be checked ' +
        'against the plan it claims to perform. Nothing was changed.',
    )
  }
  if (typeof token !== 'string' || !token) {
    throw new ToolError(
      'plan_token_required',
      'Refused: confirm: true needs the plan_token from the preview of this exact call. ' +
        'Call this tool without confirm, show the user what it reports, and pass the ' +
        'plan_token it returns. Nothing was changed.',
    )
  }
  const taken = store.take(token)
  if (!taken.ok) {
    throw new ToolError(
      taken.reason === 'expired' ? 'plan_expired' : 'unknown_plan_token',
      taken.reason === 'expired'
        ? `Refused: plan ${quote(token)} is older than ${Math.round(PLAN_TTL_MS / 60000)} minutes. ` +
          'Plan again and confirm the new plan. Nothing was changed.'
        : `Refused: plan ${quote(token)} is not a plan this server issued, or it has already ` +
          'been used. Each plan performs one change. Nothing was changed.',
    )
  }
  const body = canonical(fingerprint)
  if (body !== taken.body) {
    throw new ToolError(
      'plan_changed',
      `Refused: ${differences(taken.body, fingerprint).join(', ')} changed between the plan and ` +
        'this call, so performing it would not do what was approved. Nothing was changed; ' +
        'call again without confirm to see the current plan.',
    )
  }
}

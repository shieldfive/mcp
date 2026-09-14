// Presentation helpers.
//
// Every tool returns structured JSON as its payload. These exist so the
// human-readable summary line on top of that JSON is consistent, and so byte
// counts are never rendered by ad-hoc arithmetic in nine different files.

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

/** Decimal units, matching what Finder and Explorer show a user. */
export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return 'unknown'
  if (bytes < 1000) return `${bytes} B`
  let value = bytes
  let unit = 0
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000
    unit++
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${UNITS[unit]}`
}

export function formatDate(mtimeMs) {
  return new Date(mtimeMs).toISOString().slice(0, 10)
}

export function daysAgo(mtimeMs, now) {
  return Math.floor((now - mtimeMs) / 86_400_000)
}

/**
 * The MCP content payload for a tool result.
 *
 * A one-line summary first, then the JSON. The summary is what a model quotes
 * back to the user, so it carries the caveat when there is one — a truncated
 * scan says so on the line that gets read, not only in a field that may not be.
 */
export function toolResult(summary, data) {
  return {
    content: [
      { type: 'text', text: summary },
      { type: 'text', text: JSON.stringify(data, null, 2) },
    ],
  }
}

/** A refusal, rendered so the model can act on it rather than retry blindly. */
export function toolFailure(err) {
  const code = err?.code ?? 'error'
  return {
    isError: true,
    content: [{ type: 'text', text: `[${code}] ${err?.message ?? String(err)}` }],
  }
}

/**
 * Warnings a scan produced, as sentences worth putting in front of a user.
 *
 * Returns [] when the scan was clean, so callers can join unconditionally.
 */
export function scanWarnings(perRoot) {
  const warnings = []
  const truncated = perRoot.filter((r) => r.truncated)
  if (truncated.length) {
    warnings.push(
      `Scan stopped at the ${truncated[0].maxFiles.toLocaleString()}-file cap in ` +
        `${truncated.map((r) => r.root).join(', ')}. These results are PARTIAL — ` +
        'narrow the path or raise the cap before drawing a conclusion from them.',
    )
  }
  const unreadable = perRoot.reduce((n, r) => n + r.unreadable.length, 0)
  if (unreadable) {
    warnings.push(
      `${unreadable} item(s) could not be read (permissions or I/O) and are absent ` +
        'from these totals.',
    )
  }
  const links = perRoot.reduce((n, r) => n + r.symlinksSkipped, 0)
  if (links) {
    warnings.push(`${links} symlink(s) skipped; this server never follows them.`)
  }
  const depth = perRoot.reduce((n, r) => n + r.depthLimited.length, 0)
  if (depth) {
    warnings.push(`${depth} directory branch(es) exceeded the depth limit and were not walked.`)
  }
  return warnings
}

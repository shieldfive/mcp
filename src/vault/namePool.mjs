// A fixed pool of name-decryption workers with an in-memory cache keyed by the
// envelope itself: a renamed item has a new envelope and is decrypted again;
// an unchanged one never is. The cache dies with the process.

import { availableParallelism } from 'node:os'
import { Worker } from 'node:worker_threads'

export function createNamePool({ size = Math.max(1, Math.min(8, availableParallelism() - 1)) } = {}) {
  const workers = []
  const idle = []
  const queue = []
  const pending = new Map()
  const cache = new Map()
  let seq = 0

  function startWorker() {
    const w = new Worker(new URL('./nameWorker.mjs', import.meta.url))
    w.unref()
    w.on('message', ({ id, ok, name }) => {
      const p = pending.get(id)
      pending.delete(id)
      p?.resolve(ok ? name : null)
      idle.push(w)
      pump()
    })
    w.on('error', () => {})
    workers.push(w)
    idle.push(w)
  }

  function pump() {
    while (idle.length && queue.length) {
      const w = idle.pop()
      const job = queue.shift()
      pending.set(job.msg.id, job)
      w.postMessage(job.msg)
    }
  }

  /**
   * Decrypt one name. `key` is the parent folder key, or with direct: true the
   * already-derived name key from a grant `name` wrap. Resolves to null when
   * the envelope does not open — callers show it as unavailable, never guess.
   */
  function decrypt({ raw, key, rowId, direct = false }) {
    const cacheKey = `${rowId}|${raw}`
    if (cache.has(cacheKey)) return Promise.resolve(cache.get(cacheKey))
    if (!workers.length) for (let i = 0; i < size; i++) startWorker()
    return new Promise((resolve) => {
      const id = ++seq
      queue.push({
        msg: { id, raw, key, rowId, direct },
        resolve: (name) => {
          if (name !== null) cache.set(cacheKey, name)
          resolve(name)
        },
      })
      pump()
    })
  }

  async function close() {
    await Promise.all(workers.map((w) => w.terminate()))
    workers.length = 0
    idle.length = 0
  }

  return { decrypt, close, get cached() { return cache.size } }
}

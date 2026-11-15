"use strict";

/**
 * In-memory idempotency store. The platform treats task/turn IDs as
 * idempotency keys and may retry deliveries (rules 1.2). We cache the exact
 * raw response body per key so a retry returns byte-identical output (and the
 * same HMAC signature stays valid).
 *
 * Note: in-memory only — a cold start loses the cache. The platform's retry
 * window is short (network-failure retries), so this is acceptable; a
 * persistent store can be swapped in behind this interface.
 */
class IdempotencyStore {
  constructor(ttlMs = 24 * 3600 * 1000, maxEntries = 5000) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.done = new Map(); // key -> { body: Buffer, contentType, ts }
    this.inflight = new Map(); // key -> Promise<{body, contentType}>
  }

  async run(key, producer) {
    const hit = this.done.get(key);
    if (hit && Date.now() - hit.ts < this.ttlMs) return hit;
    if (this.inflight.has(key)) return this.inflight.get(key);
    const p = (async () => {
      const res = await producer();
      this.done.set(key, { ...res, ts: Date.now() });
      if (this.done.size > this.maxEntries) {
        const oldest = this.done.keys().next().value;
        this.done.delete(oldest);
      }
      this.inflight.delete(key);
      return res;
    })();
    this.inflight.set(key, p);
    return p;
  }
}

module.exports = { IdempotencyStore };

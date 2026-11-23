// Fleet protocol, the browser relay: a bounded sliding-minute counter (SEC H3/H4 on #58). One queue of at most `max`
// events in the last `spanMs`, with per-key counts; a key exists only while it has an event in the window, and nothing
// is allocated once the queue is full. So memory is O(max) however many distinct keys callers present.

export class MinuteWindow {
  /** clock: { now() } (monotonic); max: the events kept (the global cap); spanMs: the window. */
  constructor({ clock, max, spanMs = 60_000 }) {
    this.clock = clock; this.max = max; this.spanMs = spanMs;
    this.events = []; this.head = 0; this.counts = new Map();
  }

  #sweep() {
    const cutoff = this.clock.now() - this.spanMs;
    while (this.head < this.events.length && this.events[this.head].t <= cutoff) {
      for (const k of this.events[this.head].keys) { const n = this.counts.get(k) - 1; n ? this.counts.set(k, n) : this.counts.delete(k); }
      this.head++;
    }
    if (this.head > 1024 && this.head * 2 > this.events.length) { this.events = this.events.slice(this.head); this.head = 0; }
  }

  /** Events in the window. */
  get size() { this.#sweep(); return this.events.length - this.head; }
  /** Keys with an event in the window (the per-key map's size). */
  get keys() { this.#sweep(); return this.counts.size; }
  /** Events for `key` in the window (0 for a key never seen: nothing is allocated to answer). */
  count(key) { this.#sweep(); return this.counts.get(key) ?? 0; }

  /**
   * Record one event for `keys` if the window has room and each key is under `perKey`. Returns false (and allocates
   * nothing) otherwise.
   */
  take(keys, perKey = Infinity) {
    this.#sweep();
    if (this.events.length - this.head >= this.max) return false;
    for (const k of keys) if ((this.counts.get(k) ?? 0) >= perKey) return false;
    this.events.push({ t: this.clock.now(), keys });
    for (const k of keys) this.counts.set(k, (this.counts.get(k) ?? 0) + 1);
    return true;
  }
}

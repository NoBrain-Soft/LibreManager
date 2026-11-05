// Shared, coarse "now" so relative times re-render together without each
// component calling Date.now() during render.

import { useSyncExternalStore } from 'react';

const TICK_MS = 15_000;

let current = Date.now();
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;

function subscribe(l: () => void) {
  listeners.add(l);
  if (!timer) {
    current = Date.now();
    timer = setInterval(() => {
      current = Date.now();
      for (const fn of listeners) fn();
    }, TICK_MS);
  }
  return () => {
    listeners.delete(l);
    if (listeners.size === 0 && timer) {
      clearInterval(timer);
      timer = null;
    }
  };
}

export function useNow(): number {
  return useSyncExternalStore(
    subscribe,
    () => current,
    () => current,
  );
}

/** Current time for event handlers / effects (not during render). */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

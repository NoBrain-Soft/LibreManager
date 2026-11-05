// Light/dark theme: follows the OS by default, with a manual override.
// Applied from the main bundle (no inline script, CSP-safe). The preference
// is a non-sensitive UI setting, the only thing kept in Web Storage.

import { useSyncExternalStore } from 'react';

export type ThemePref = 'system' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'stellwerk.theme';

function storage(): Storage | null {
  try {
    // eslint-disable-next-line no-restricted-properties -- theme preference only, never tokens
    return window.localStorage;
  } catch {
    return null;
  }
}

function readPref(): ThemePref {
  const v = storage()?.getItem(STORAGE_KEY);
  return v === 'light' || v === 'dark' || v === 'system' ? v : 'system';
}

const media = typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)') : null;

let pref: ThemePref = typeof window !== 'undefined' ? readPref() : 'system';
let snapshot = { pref, resolved: resolve(pref) };
const listeners = new Set<() => void>();

function resolve(p: ThemePref): ResolvedTheme {
  if (p === 'system') return media?.matches ? 'dark' : 'light';
  return p;
}

function apply() {
  const resolved = resolve(pref);
  snapshot = { pref, resolved };
  const root = document.documentElement;
  root.classList.toggle('dark', resolved === 'dark');
  root.dataset.theme = resolved;
  for (const l of listeners) l();
}

export function initTheme(): void {
  apply();
  media?.addEventListener('change', () => {
    if (pref === 'system') apply();
  });
  window.addEventListener('storage', (e) => {
    if (e.key === STORAGE_KEY) {
      pref = readPref();
      apply();
    }
  });
}

export function setThemePref(p: ThemePref): void {
  pref = p;
  try {
    storage()?.setItem(STORAGE_KEY, p);
  } catch {
    /* storage full or blocked: keep in memory */
  }
  apply();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useTheme(): { pref: ThemePref; resolved: ResolvedTheme } {
  return useSyncExternalStore(subscribe, () => snapshot, () => snapshot);
}

/** Read a CSS custom property from :root (for canvas-based charts/terminals). */
export function cssVar(name: string, fallback = ''): string {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

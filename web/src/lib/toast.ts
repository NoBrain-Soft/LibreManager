// Tiny toast store (rendered by <Toaster/>). Messages are plain text.

import { useSyncExternalStore } from 'react';

export type ToastVariant = 'default' | 'success' | 'error';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastItem {
  id: number;
  title: string;
  description?: string;
  variant: ToastVariant;
  action?: ToastAction;
  duration: number;
}

type Listener = () => void;

let items: ToastItem[] = [];
let nextId = 1;
const listeners = new Set<Listener>();

function emit() {
  for (const l of listeners) l();
}

export function toast(t: { title: string; description?: string; variant?: ToastVariant; action?: ToastAction; duration?: number }): number {
  const id = nextId++;
  const item: ToastItem = {
    id,
    title: t.title,
    variant: t.variant ?? 'default',
    duration: t.duration ?? (t.variant === 'error' ? 8000 : 5000),
    ...(t.description ? { description: t.description } : {}),
    ...(t.action ? { action: t.action } : {}),
  };
  items = [...items.slice(-4), item];
  emit();
  return id;
}

export function dismissToast(id: number): void {
  items = items.filter((t) => t.id !== id);
  emit();
}

function subscribe(l: Listener) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useToasts(): ToastItem[] {
  return useSyncExternalStore(subscribe, () => items, () => items);
}

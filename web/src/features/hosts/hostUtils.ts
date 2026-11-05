import { useQuery } from '@tanstack/react-query';
import { useParams } from '@tanstack/react-router';
import { hostQuery } from '@/api/queries';
import type { Host } from '@/api/types';

export function osLabel(h: Pick<Host, 'os_pretty_name' | 'os_id' | 'os_version'>): string {
  return h.os_pretty_name || [h.os_id, h.os_version].filter(Boolean).join(' ') || '–';
}

/** hostId of the current /hosts/$hostId route. */
export function useHostId(): string {
  const params = useParams({ strict: false });
  const id = (params as { hostId?: string }).hostId;
  if (!id) throw new Error('useHostId used outside /hosts/$hostId');
  return id;
}

/** The current host (shared cache with the host layout header). */
export function useCurrentHost() {
  return useQuery(hostQuery(useHostId()));
}

/** Read a boolean-ish flag from the host's informational policy summary. */
export function policyFlag(host: Pick<Host, 'policy'> | undefined, key: string): boolean | undefined {
  const p = host?.policy;
  if (!p) return undefined;
  const camel = key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  const v = (p as Record<string, unknown>)[key] ?? (p as Record<string, unknown>)[camel];
  return typeof v === 'boolean' ? v : undefined;
}

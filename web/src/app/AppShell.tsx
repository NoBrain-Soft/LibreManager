import { useQuery } from '@tanstack/react-query';
import { Outlet, useRouter, useRouterState } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { events } from '@/api/events';
import { refreshSession, sessionQuery } from '@/api/session';
import { cn } from '@/lib/utils';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/** Authenticated layout: sidebar, top bar, live events, session watch. */
export function AppShell() {
  const [navOpen, setNavOpen] = useState(false);
  const { data: session, isFetched } = useQuery(sessionQuery);
  const router = useRouter();
  const href = useRouterState({ select: (s) => s.location.href });
  const active = session?.state === 'active';

  // Session expired or downgraded (e.g. idle timeout) → back to login.
  useEffect(() => {
    if (isFetched && !active) {
      void router.navigate({ to: '/login', search: { redirect: href }, replace: true });
    }
  }, [active, isFetched, href, router]);

  useEffect(() => {
    if (!active) return;
    events.onAuthFailure = () => void refreshSession();
    events.start();
    return () => {
      events.onAuthFailure = null;
      events.stop();
    };
  }, [active]);

  if (!active) return null;

  return (
    <div className="flex h-full">
      <a
        href="#main"
        className="sr-only z-50 rounded bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Skip to content
      </a>
      <aside className="hidden w-56 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal aria-label="Navigation">
          <button type="button" className="absolute inset-0 bg-black/40" aria-label="Close navigation" onClick={() => setNavOpen(false)} />
          <div className={cn('absolute inset-y-0 left-0 w-60 shadow-xl')}>
            <Sidebar onNavigate={() => setNavOpen(false)} />
          </div>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setNavOpen(true)} />
        <main id="main" className="min-h-0 flex-1 overflow-y-auto scrollbar-thin" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

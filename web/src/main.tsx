import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { queryClient } from '@/api/queryClient';
import { clearSessionData } from '@/api/session';
import { initTheme } from '@/app/theme';
import { setUnauthenticatedHandler } from '@/auth/unauthenticated';
import { TooltipProvider } from '@/components/ui/tooltip';
import { buildRouter } from './router';
import './index.css';

initTheme();

const router = buildRouter(queryClient);

// Any API call answering `unauthenticated` ends the local session state.
setUnauthenticatedHandler(() => {
  const { pathname, href } = router.state.location;
  clearSessionData();
  if (!pathname.startsWith('/login')) {
    void router.navigate({ to: '/login', search: { redirect: href }, replace: true });
  }
});

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root missing');

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={300}>
        <RouterProvider router={router} />
      </TooltipProvider>
    </QueryClientProvider>
  </StrictMode>,
);

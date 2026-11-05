import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query';
import { notifyUnauthenticated } from '@/auth/unauthenticated';
import { isApiError } from './errors';

const NO_RETRY_STATUS = new Set([400, 401, 403, 404, 409, 422, 429]);

function onError(err: unknown): void {
  if (isApiError(err) && err.code === 'unauthenticated') notifyUnauthenticated();
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError }),
  mutationCache: new MutationCache({ onError }),
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: true,
      retry: (count, err) => {
        if (isApiError(err) && (NO_RETRY_STATUS.has(err.status) || err.code === 'stepup_required')) return false;
        return count < 2;
      },
    },
    mutations: {
      retry: false,
    },
  },
});

import { errorMessage, StepUpCancelledError } from '@/api/errors';
import { toast } from './toast';

/** Toast an error, except when the user just cancelled a step-up prompt. */
export function notifyError(e: unknown, title = 'Action failed'): void {
  if (e instanceof StepUpCancelledError) return;
  toast({ title, description: errorMessage(e), variant: 'error' });
}

export function notifySuccess(title: string, description?: string): void {
  toast({ title, variant: 'success', ...(description ? { description } : {}) });
}

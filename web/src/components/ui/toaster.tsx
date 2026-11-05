import { CircleAlertIcon, CircleCheckIcon, InfoIcon, XIcon } from 'lucide-react';
import { Toast } from 'radix-ui';
import { dismissToast, useToasts } from '@/lib/toast';
import { cn } from '@/lib/utils';

export function Toaster() {
  const items = useToasts();
  return (
    <Toast.Provider swipeDirection="right">
      {items.map((t) => {
        const Icon = t.variant === 'success' ? CircleCheckIcon : t.variant === 'error' ? CircleAlertIcon : InfoIcon;
        return (
          <Toast.Root
            key={t.id}
            duration={t.duration}
            onOpenChange={(open) => {
              if (!open) dismissToast(t.id);
            }}
            className="pointer-events-auto flex w-full items-start gap-3 rounded-lg border bg-popover p-3 pr-8 text-popover-foreground shadow-lg"
            type={t.variant === 'error' ? 'foreground' : 'background'}
          >
            <Icon
              className={cn(
                'mt-0.5 size-4 shrink-0',
                t.variant === 'success' && 'text-good',
                t.variant === 'error' && 'text-critical',
                t.variant === 'default' && 'text-info',
              )}
              aria-hidden
            />
            <div className="grid min-w-0 gap-0.5">
              <Toast.Title className="text-sm font-medium">{t.title}</Toast.Title>
              {t.description && (
                <Toast.Description className="break-words text-xs text-muted-foreground">{t.description}</Toast.Description>
              )}
              {t.action && (
                <Toast.Action altText={t.action.label} asChild>
                  <button
                    type="button"
                    className="mt-1 w-fit text-xs font-medium text-primary hover:underline"
                    onClick={t.action.onClick}
                  >
                    {t.action.label}
                  </button>
                </Toast.Action>
              )}
            </div>
            <Toast.Close
              className="absolute right-2 top-2 rounded-sm p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
              aria-label="Dismiss"
            >
              <XIcon className="size-3.5" />
            </Toast.Close>
          </Toast.Root>
        );
      })}
      <Toast.Viewport className="fixed bottom-0 right-0 z-[100] flex w-full max-w-sm flex-col gap-2 p-4 outline-none" />
    </Toast.Provider>
  );
}

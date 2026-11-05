import { useQuery } from '@tanstack/react-query';
import { ShieldCheckIcon } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { StepUpCancelledError } from '@/api/errors';
import { refreshSession, sessionQuery } from '@/api/session';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { MfaVerifyPanel } from './MfaVerifyPanel';
import { setStepUpHandler } from './stepup';

interface Pending {
  resolve: () => void;
  reject: (e: unknown) => void;
}

/**
 * Mounted once at the app root. When an API call answers
 * `stepup_required`, withStepUp() opens this dialog; the action is retried
 * after a successful WebAuthn/TOTP verification.
 */
export function StepUpDialog() {
  const [open, setOpen] = useState(false);
  const pending = useRef<Pending | null>(null);
  const { data: session } = useQuery(sessionQuery);

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<void>((resolve, reject) => {
          pending.current = { resolve, reject };
          setOpen(true);
        }),
    );
    return () => {
      setStepUpHandler(null);
      pending.current?.reject(new StepUpCancelledError());
      pending.current = null;
    };
  }, []);

  const finish = (ok: boolean) => {
    const p = pending.current;
    pending.current = null;
    setOpen(false);
    if (ok) p?.resolve();
    else p?.reject(new StepUpCancelledError());
  };

  const methods = {
    webauthn: (session?.mfa.webauthn ?? 0) > 0,
    totp: session?.mfa.totp ?? false,
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) finish(false);
      }}
    >
      <DialogContent size="sm" onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4 text-primary" /> Confirm it is you
          </DialogTitle>
          <DialogDescription>
            This action needs a recent re-authentication. It stays valid for a few minutes.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {open && (
            <MfaVerifyPanel
              methods={methods}
              onVerified={async () => {
                await refreshSession();
                finish(true);
              }}
            />
          )}
        </DialogBody>
      </DialogContent>
    </Dialog>
  );
}

import { useId, useState, type ReactNode } from 'react';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Callout } from './states';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  /** When set, the user must type this exact text to enable the button. */
  typeToConfirm?: string;
  /** Runs on confirm; the dialog closes when it resolves and shows the error otherwise. */
  onConfirm: () => unknown;
}

export function ConfirmDialog(props: Props) {
  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      {props.open && <ConfirmBody {...props} />}
    </Dialog>
  );
}

function ConfirmBody({
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = 'Confirm',
  destructive,
  typeToConfirm,
  onConfirm,
}: Props) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inputId = useId();
  const ready = !typeToConfirm || typed === typeToConfirm;

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <DialogContent size="sm">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="contents"
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogBody className="grid gap-3">
          {children}
          {typeToConfirm && (
            <div className="grid gap-1.5">
              <Label htmlFor={inputId}>
                Type <span className="rounded bg-muted px-1 font-mono">{typeToConfirm}</span> to confirm
              </Label>
              <Input
                id={inputId}
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                autoFocus
              />
            </div>
          )}
          {error !== null && <Callout tone="critical" title="Action failed">{errorMessage(error)}</Callout>}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" variant={destructive ? 'destructive' : 'default'} disabled={!ready || busy}>
            {busy ? 'Working…' : confirmLabel}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

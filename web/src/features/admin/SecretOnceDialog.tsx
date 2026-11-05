import { TriangleAlertIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { CodeBlock } from '@/components/common/CopyButton';
import { Callout } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  secrets: { label: string; value: string }[];
  children?: ReactNode;
}

/** Shows server-generated secrets exactly once. Closing discards them. */
export function SecretOnceDialog({ open, onClose, title, description, secrets, children }: Props) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="lg" onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogBody className="grid gap-3">
          <Callout tone="warning" icon={TriangleAlertIcon} title="Shown only once">
            Copy it now and hand it over through a secure channel. It cannot be displayed again.
          </Callout>
          {secrets.map((s) => (
            <div key={s.label} className="grid gap-1">
              <div className="text-xs font-medium text-muted-foreground">{s.label}</div>
              <CodeBlock text={s.value} />
            </div>
          ))}
          {children}
        </DialogBody>
        <DialogFooter>
          <Button onClick={onClose}>I have copied it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

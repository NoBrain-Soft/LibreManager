import { CheckIcon, CopyIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from '@/lib/toast';
import { cn, copyText } from '@/lib/utils';

interface Props {
  text: string;
  label?: string;
  className?: string;
  size?: 'sm' | 'icon-sm';
  variant?: 'outline' | 'ghost' | 'secondary';
}

export function CopyButton({ text, label, className, size = 'sm', variant = 'outline' }: Props) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1800);
    return () => clearTimeout(t);
  }, [copied]);

  const onCopy = async () => {
    if (await copyText(text)) setCopied(true);
    else toast({ title: 'Copy failed', description: 'Select the text and copy it manually.', variant: 'error' });
  };

  const iconOnly = size === 'icon-sm' || !label;
  return (
    <Button
      variant={variant}
      size={iconOnly ? 'icon-sm' : size}
      className={className}
      onClick={onCopy}
      aria-label={label ?? 'Copy to clipboard'}
      title={label ?? 'Copy to clipboard'}
    >
      {copied ? <CheckIcon className="text-good" /> : <CopyIcon />}
      {!iconOnly && <span>{copied ? 'Copied' : label}</span>}
    </Button>
  );
}

/** Monospace, selectable block with a copy button. Text is rendered as text. */
export function CodeBlock({ text, className, label = 'Copy' }: { text: string; className?: string; label?: string }) {
  return (
    <div className={cn('relative rounded-md border bg-muted/60', className)}>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all p-3 pr-24 font-mono text-xs leading-relaxed scrollbar-thin">
        {text}
      </pre>
      <CopyButton text={text} label={label} className="absolute right-2 top-2" />
    </div>
  );
}

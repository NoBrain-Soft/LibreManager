import type { ComponentProps } from 'react';
import { cn } from '@/lib/utils';

const fieldBase =
  'w-full min-w-0 rounded-md border border-input bg-card px-2.5 text-sm shadow-xs transition-colors placeholder:text-muted-foreground/80 focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive';

export function Input({ className, type = 'text', ...props }: ComponentProps<'input'>) {
  return <input type={type} data-slot="input" className={cn(fieldBase, 'h-8 py-1', className)} {...props} />;
}

export function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn(fieldBase, 'min-h-16 py-1.5', className)} {...props} />;
}

/** Native select styled like the other fields (accessible, keyboard friendly). */
export function NativeSelect({ className, children, ...props }: ComponentProps<'select'>) {
  return (
    <select data-slot="select" className={cn(fieldBase, 'h-8 cursor-pointer appearance-auto py-1 pr-1', className)} {...props}>
      {children}
    </select>
  );
}

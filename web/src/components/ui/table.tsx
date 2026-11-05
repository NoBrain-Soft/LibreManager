import type { ComponentProps } from 'react';
import { cn } from '@/lib/utils';

export function Table({ className, wrapperClassName, ...props }: ComponentProps<'table'> & { wrapperClassName?: string }) {
  return (
    <div className={cn('relative w-full overflow-x-auto scrollbar-thin', wrapperClassName)}>
      <table className={cn('w-full caption-bottom border-collapse text-sm', className)} {...props} />
    </div>
  );
}

export function THead({ className, ...props }: ComponentProps<'thead'>) {
  return <thead className={cn('[&_tr]:border-b', className)} {...props} />;
}

export function TBody({ className, ...props }: ComponentProps<'tbody'>) {
  return <tbody className={cn('[&_tr:last-child]:border-0', className)} {...props} />;
}

export function TR({ className, ...props }: ComponentProps<'tr'>) {
  return (
    <tr
      className={cn('border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-primary/6', className)}
      {...props}
    />
  );
}

export function TH({ className, ...props }: ComponentProps<'th'>) {
  return (
    <th
      className={cn(
        'h-8 whitespace-nowrap px-3 text-left align-middle text-xs font-medium text-muted-foreground [&:has([role=checkbox])]:w-8 [&:has([role=checkbox])]:pr-0',
        className,
      )}
      {...props}
    />
  );
}

export function TD({ className, ...props }: ComponentProps<'td'>) {
  return (
    <td
      className={cn('px-3 py-1.5 align-middle tabular [&:has([role=checkbox])]:w-8 [&:has([role=checkbox])]:pr-0', className)}
      {...props}
    />
  );
}

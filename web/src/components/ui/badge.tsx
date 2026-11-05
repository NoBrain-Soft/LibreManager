import type { ComponentProps } from 'react';
import { cn } from '@/lib/utils';
import { type BadgeVariantProps, badgeVariants } from './variants';

export function Badge({ className, variant, ...props }: ComponentProps<'span'> & BadgeVariantProps) {
  return <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />;
}

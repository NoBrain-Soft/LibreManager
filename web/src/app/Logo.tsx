import { cn } from '@/lib/utils';

/** Signal-box mark: three tracks with switch points. */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn('size-6', className)} aria-hidden>
      <rect width="32" height="32" rx="7" fill="var(--primary)" />
      <path d="M8 22h16M8 16h16M8 10h16" stroke="var(--primary-foreground)" strokeOpacity="0.55" strokeWidth="2" strokeLinecap="round" />
      <circle cx="12" cy="10" r="2.6" fill="var(--primary-foreground)" />
      <circle cx="20" cy="16" r="2.6" fill="var(--primary-foreground)" />
      <circle cx="14" cy="22" r="2.6" fill="var(--primary-foreground)" />
    </svg>
  );
}

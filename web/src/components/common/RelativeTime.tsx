import { Tip } from '@/components/ui/tooltip';
import { formatDateTime, formatRelative, parseDate } from '@/lib/format';
import { useNow } from '@/lib/now';
import { cn } from '@/lib/utils';

interface Props {
  value: string | null | undefined;
  className?: string;
  /** Text when the value is missing. */
  fallback?: string;
}

/** "5 min. ago" with the absolute local + UTC time in a tooltip. */
export function RelativeTime({ value, className, fallback = '–' }: Props) {
  const now = useNow();
  const d = parseDate(value);
  if (!d) return <span className={cn('text-muted-foreground', className)}>{fallback}</span>;
  return (
    <Tip
      content={
        <span className="grid">
          <span>{formatDateTime(d)}</span>
          <span className="opacity-70">{d.toISOString()}</span>
        </span>
      }
    >
      <time dateTime={d.toISOString()} tabIndex={0} className={cn('whitespace-nowrap tabular outline-none', className)}>
        {formatRelative(d, now)}
      </time>
    </Tip>
  );
}

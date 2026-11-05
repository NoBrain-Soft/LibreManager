import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { LogOutIcon, MenuIcon, MonitorIcon, MoonIcon, SunIcon, UserIcon } from 'lucide-react';
import { useEventsStatus } from '@/api/events';
import { sessionQuery } from '@/api/session';
import { logout } from '@/auth/mfa';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tip } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { setThemePref, type ThemePref, useTheme } from './theme';

export function Topbar({ onMenu }: { onMenu: () => void }) {
  return (
    <header className="flex h-12 shrink-0 items-center gap-2 border-b bg-card px-3 lg:px-4">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onMenu} aria-label="Open navigation">
        <MenuIcon />
      </Button>
      <div className="flex-1" />
      <EventsIndicator />
      <ThemeMenu />
      <UserMenu />
    </header>
  );
}

function EventsIndicator() {
  const status = useEventsStatus();
  const spec = {
    open: { label: 'Live', dot: 'bg-good', tip: 'Live updates connected.' },
    connecting: { label: 'Connecting', dot: 'bg-warning animate-pulse', tip: 'Connecting to live updates…' },
    reconnecting: {
      label: 'Reconnecting',
      dot: 'bg-serious animate-pulse',
      tip: 'Live updates disconnected; data refreshes by polling until the connection is back.',
    },
    idle: { label: 'Offline', dot: 'bg-neutral', tip: 'Live updates are not connected.' },
  }[status];
  return (
    <Tip content={spec.tip}>
      <span
        tabIndex={0}
        role="status"
        aria-live="polite"
        className="flex h-7 items-center gap-1.5 rounded-md px-2 text-xs text-muted-foreground outline-none"
      >
        <span className={cn('size-2 rounded-full', spec.dot)} aria-hidden />
        {spec.label}
      </span>
    </Tip>
  );
}

function ThemeMenu() {
  const { pref, resolved } = useTheme();
  const Icon = resolved === 'dark' ? MoonIcon : SunIcon;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Theme">
          <Icon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <DropdownMenuLabel>Theme</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={pref} onValueChange={(v) => setThemePref(v as ThemePref)}>
          <DropdownMenuRadioItem value="system">
            <MonitorIcon /> System
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="light">
            <SunIcon /> Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">
            <MoonIcon /> Dark
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function UserMenu() {
  const { data: session } = useQuery(sessionQuery);
  const navigate = useNavigate();
  const user = session?.user;
  const initials = (user?.display_name || user?.username || '?')
    .split(/\s+/)
    .map((p) => p[0] ?? '')
    .join('')
    .slice(0, 2)
    .toUpperCase();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-8 gap-2 px-1.5" aria-label="User menu">
          <span className="flex size-6 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-foreground">
            {initials}
          </span>
          <span className="hidden max-w-40 truncate text-sm sm:inline">{user?.display_name || user?.username}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-52">
        <DropdownMenuLabel className="grid">
          <span className="truncate text-sm font-medium text-foreground">{user?.display_name || user?.username}</span>
          <span className="truncate font-normal">{user?.username}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/account">
            <UserIcon /> Account & security
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={() => {
            void logout().then(() => navigate({ to: '/login' }));
          }}
        >
          <LogOutIcon /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

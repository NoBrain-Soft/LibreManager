import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import {
  BellIcon,
  FolderTreeIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  ListChecksIcon,
  type LucideIcon,
  PackageIcon,
  ScrollTextIcon,
  ServerIcon,
  SettingsIcon,
  ShieldCheckIcon,
  TerminalIcon,
  UsersIcon,
} from 'lucide-react';
import { dashboardQuery } from '@/api/queries';
import { usePermissions } from '@/auth/usePermissions';
import type { Permission } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { Logo } from './Logo';

interface NavItem {
  to:
    | '/dashboard'
    | '/hosts'
    | '/jobs'
    | '/updates'
    | '/security'
    | '/alerts'
    | '/admin/users'
    | '/admin/groups'
    | '/admin/enrollment'
    | '/admin/audit'
    | '/admin/shell-sessions'
    | '/admin/settings';
  label: string;
  icon: LucideIcon;
  perm?: Permission;
  badge?: 'alerts';
}

const MAIN: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboardIcon },
  { to: '/hosts', label: 'Hosts', icon: ServerIcon, perm: 'host.view' },
  { to: '/jobs', label: 'Jobs', icon: ListChecksIcon, perm: 'job.view' },
  { to: '/updates', label: 'Updates', icon: PackageIcon, perm: 'host.view' },
  { to: '/security', label: 'Security', icon: ShieldCheckIcon, perm: 'security.view' },
  { to: '/alerts', label: 'Alerts', icon: BellIcon, perm: 'alerts.view', badge: 'alerts' },
];

const ADMIN: NavItem[] = [
  { to: '/admin/users', label: 'Users', icon: UsersIcon, perm: 'admin.users' },
  { to: '/admin/groups', label: 'Host groups', icon: FolderTreeIcon, perm: 'admin.groups' },
  { to: '/admin/enrollment', label: 'Enrollment', icon: KeyRoundIcon, perm: 'enroll.manage' },
  { to: '/admin/audit', label: 'Audit log', icon: ScrollTextIcon, perm: 'audit.view' },
  { to: '/admin/shell-sessions', label: 'Shell sessions', icon: TerminalIcon, perm: 'shell.review' },
  { to: '/admin/settings', label: 'Settings', icon: SettingsIcon, perm: 'admin.settings' },
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const perms = usePermissions();
  const visible = (items: NavItem[]) => items.filter((i) => !i.perm || perms.canAnywhere(i.perm));
  const main = visible(MAIN);
  const admin = visible(ADMIN);
  const { data: dash } = useQuery({ ...dashboardQuery, enabled: perms.canAnywhere('alerts.view') });
  const firing = dash?.alerts_firing ?? 0;

  return (
    <nav aria-label="Main" className="flex h-full flex-col gap-4 overflow-y-auto border-r border-sidebar-border bg-sidebar px-2 py-3 scrollbar-thin">
      <Link to="/dashboard" className="flex items-center gap-2 px-2 py-1" onClick={onNavigate}>
        <Logo />
        <span className="text-[15px] font-semibold tracking-tight">Stellwerk</span>
      </Link>
      <ul className="grid gap-0.5">
        {main.map((item) => (
          <NavLink key={item.to} item={item} onNavigate={onNavigate} count={item.badge === 'alerts' ? firing : 0} />
        ))}
      </ul>
      {admin.length > 0 && (
        <div>
          <div className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Administration</div>
          <ul className="grid gap-0.5">
            {admin.map((item) => (
              <NavLink key={item.to} item={item} onNavigate={onNavigate} count={0} />
            ))}
          </ul>
        </div>
      )}
    </nav>
  );
}

function NavLink({ item, onNavigate, count }: { item: NavItem; onNavigate?: (() => void) | undefined; count: number }) {
  const Icon = item.icon;
  return (
    <li>
      <Link
        to={item.to}
        onClick={onNavigate}
        className="group flex h-8 items-center gap-2.5 rounded-md px-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        activeProps={{ className: cn('bg-accent !text-foreground font-medium'), 'aria-current': 'page' }}
      >
        <Icon className="size-4 shrink-0" aria-hidden />
        <span className="flex-1 truncate">{item.label}</span>
        {count > 0 && (
          <span
            className="rounded-sm bg-critical px-1.5 text-[11px] font-semibold leading-4 text-white tabular"
            aria-label={`${count} firing`}
          >
            {count}
          </span>
        )}
      </Link>
    </li>
  );
}

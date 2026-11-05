import { Link, Outlet, useRouter, type ErrorComponentProps } from '@tanstack/react-router';
import { CompassIcon } from 'lucide-react';
import { StepUpDialog } from '@/auth/StepUpDialog';
import { EmptyState, ErrorState } from '@/components/common/states';
import { Button } from '@/components/ui/button';
import { Toaster } from '@/components/ui/toaster';

export function RootLayout() {
  return (
    <>
      <Outlet />
      <StepUpDialog />
      <Toaster />
    </>
  );
}

export function NotFound() {
  return (
    <EmptyState
      icon={CompassIcon}
      title="Page not found"
      description="The page you are looking for does not exist or was moved."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/dashboard">Go to dashboard</Link>
        </Button>
      }
      className="min-h-[50vh]"
    />
  );
}

export function RouteError({ error, reset }: ErrorComponentProps) {
  const router = useRouter();
  return (
    <ErrorState
      error={error}
      className="min-h-[50vh]"
      onRetry={() => {
        reset();
        void router.invalidate();
      }}
    />
  );
}

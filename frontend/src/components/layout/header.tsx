import { useHealth } from "@/hooks/use-health";
import { useAuth } from "@/auth/useAuth";
import { cn } from "@/lib/utils";
import { Activity, LogOut } from "lucide-react";

export function Header() {
  const { data: health } = useHealth();
  const { authEnabled, user, signOut } = useAuth();
  const status = health?.status ?? "unknown";

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-background px-6">
      <div />
      <div className="flex items-center gap-4">
        {/* User identity + sign-out, only when auth is enabled.  In
            disabled mode this renders nothing — the community
            quickstart shouldn't surface auth controls that don't apply. */}
        {authEnabled && user && (
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">
              {user.displayName || user.upn}
              {user.role && (
                <span
                  className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs uppercase tracking-wide"
                  title={`OIDC role: ${user.role}`}
                >
                  {user.role}
                </span>
              )}
            </span>
            <button
              type="button"
              onClick={() => void signOut()}
              className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
              title="Sign out"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign out
            </button>
          </div>
        )}

        <div
          className="flex items-center gap-2 text-sm text-muted-foreground"
          title={
            status === "ok"
              ? "All services healthy"
              : status === "degraded"
                ? "Some services degraded"
                : "Checking health..."
          }
        >
          <Activity className="h-4 w-4" />
          <div
            className={cn(
              "h-2.5 w-2.5 rounded-full",
              status === "ok" && "bg-emerald-500",
              status === "degraded" && "bg-amber-500",
              status === "unknown" && "bg-muted-foreground"
            )}
          />
        </div>
      </div>
    </header>
  );
}

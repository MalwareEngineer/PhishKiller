import { useHealth } from "@/hooks/use-health";
import { cn } from "@/lib/utils";
import { Activity } from "lucide-react";

export function Header() {
  const { data: health } = useHealth();
  const status = health?.status ?? "unknown";

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-background px-6">
      <div />
      <div className="flex items-center gap-3">
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

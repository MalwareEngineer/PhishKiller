import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { KitStatus } from "@/types/api";

const statusConfig: Record<KitStatus, { label: string; className: string }> = {
  pending: { label: "Pending", className: "bg-slate-500/20 text-slate-400 border-slate-500/30" },
  downloading: { label: "Downloading", className: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  downloaded: { label: "Downloaded", className: "bg-sky-500/20 text-sky-400 border-sky-500/30" },
  analyzing: { label: "Analyzing", className: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  analyzed: { label: "Analyzed", className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  failed: { label: "Failed", className: "bg-red-500/20 text-red-400 border-red-500/30" },
};

export function KitStatusBadge({ status }: { status: KitStatus }) {
  const config = statusConfig[status] ?? { label: status, className: "" };
  return (
    <Badge variant="outline" className={cn("text-xs font-medium", config.className)}>
      {config.label}
    </Badge>
  );
}

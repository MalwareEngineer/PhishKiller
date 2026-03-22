import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { IndicatorType } from "@/types/api";

const typeConfig: Record<IndicatorType, { label: string; className: string }> = {
  email: { label: "Email", className: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  telegram_bot_token: { label: "TG Bot Token", className: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  telegram_chat_id: { label: "TG Chat ID", className: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  c2_url: { label: "C2 URL", className: "bg-red-500/20 text-red-400 border-red-500/30" },
  ip_address: { label: "IP", className: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  smtp_credential: { label: "SMTP Cred", className: "bg-rose-500/20 text-rose-400 border-rose-500/30" },
  base64_block: { label: "Base64", className: "bg-slate-500/20 text-slate-400 border-slate-500/30" },
  domain: { label: "Domain", className: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  phone_number: { label: "Phone", className: "bg-teal-500/20 text-teal-400 border-teal-500/30" },
  cryptocurrency_wallet: { label: "Crypto", className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  source_url: { label: "Source URL", className: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30" },
};

export function IocTypeBadge({ type }: { type: IndicatorType }) {
  const config = typeConfig[type] ?? { label: type, className: "" };
  return (
    <Badge variant="outline" className={cn("text-xs font-medium", config.className)}>
      {config.label}
    </Badge>
  );
}

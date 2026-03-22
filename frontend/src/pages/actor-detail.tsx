import { useParams } from "react-router-dom";
import { useActor } from "@/hooks/use-actors";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function ActorDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: actor, isLoading } = useActor(id!);

  if (isLoading || !actor) return <PageLoading />;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">{actor.name}</h1>

      <Card>
        <CardContent className="grid gap-4 p-4 md:grid-cols-2">
          <div>
            <span className="text-xs text-muted-foreground">Aliases</span>
            <div className="flex flex-wrap gap-1 mt-1">
              {(actor.aliases ?? []).map((a) => (
                <Badge key={a} variant="outline">{a}</Badge>
              ))}
              {(!actor.aliases || actor.aliases.length === 0) && <span className="text-sm">—</span>}
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Description</span>
            <p className="text-sm mt-1">{actor.description ?? "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Email Addresses</span>
            <div className="space-y-1 mt-1">
              {(actor.email_addresses ?? []).map((e) => (
                <p key={e} className="font-mono text-xs">{e}</p>
              ))}
              {(!actor.email_addresses || actor.email_addresses.length === 0) && <span className="text-sm">—</span>}
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Telegram Handles</span>
            <div className="space-y-1 mt-1">
              {(actor.telegram_handles ?? []).map((t) => (
                <p key={t} className="font-mono text-xs">{t}</p>
              ))}
              {(!actor.telegram_handles || actor.telegram_handles.length === 0) && <span className="text-sm">—</span>}
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">First Seen</span>
            <p className="text-sm mt-1">{actor.first_seen ?? "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Last Seen</span>
            <p className="text-sm mt-1">{actor.last_seen ?? "—"}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

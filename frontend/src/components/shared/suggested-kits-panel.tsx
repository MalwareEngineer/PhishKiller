import { Link } from "react-router-dom";
import {
  usePhishMatchSuggestionsForEntity,
  useAttributeKit,
} from "@/hooks/use-phishmatch";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sparkles, Plus, ExternalLink } from "lucide-react";
import { toast } from "sonner";
import type { PhishMatchEntityType } from "@/lib/api";

/**
 * Side panel shown on Actor / Family / Campaign detail pages — lists
 * unattributed kits that score highly against this entity and offers a
 * one-click "attribute (suspected)" action.
 *
 * The list is always filtered to unattributed kits (the backend already
 * excludes kits linked to this entity from its suggestions response).
 */
export function SuggestedKitsPanel({
  entityType,
  entityId,
  entityName,
  limit = 10,
}: {
  entityType: PhishMatchEntityType;
  entityId: string;
  entityName: string;
  limit?: number;
}) {
  const { data, isLoading } = usePhishMatchSuggestionsForEntity(
    entityType,
    entityId,
    limit,
  );
  const attributeMutation = useAttributeKit();

  if (isLoading) {
    return (
      <Card>
        <CardContent className="py-4 text-xs text-muted-foreground">
          Loading suggestions…
        </CardContent>
      </Card>
    );
  }

  const suggestions = data?.suggestions ?? [];

  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-emerald-500" />
          <h3 className="text-sm font-semibold">PhishMatch suggestions</h3>
          <Badge variant="secondary" className="ml-auto text-[10px]">
            {suggestions.length}
          </Badge>
        </div>

        {suggestions.length === 0 ? (
          <p className="py-3 text-center text-xs text-muted-foreground">
            No unattributed kits score above the threshold for this {entityType}.
          </p>
        ) : (
          <div className="space-y-2">
            {suggestions.map((s) => (
              <div
                key={s.kit_id}
                className="rounded border p-2 space-y-1.5"
              >
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <Link
                      to={`/kits/${s.kit_id}`}
                      className="block truncate text-xs text-blue-400 hover:underline"
                      title={s.source_url}
                    >
                      {s.source_url}
                    </Link>
                    <div className="mt-0.5 flex flex-wrap gap-1 text-[10px] text-muted-foreground">
                      {s.signals.tlsh > 0 && (
                        <span>TLSH {s.signals.tlsh.toFixed(0)}</span>
                      )}
                      {s.signals.ioc > 0 && (
                        <span>IOC {s.signals.ioc.toFixed(0)}</span>
                      )}
                      {s.signals.yara > 0 && (
                        <span>YARA {s.signals.yara.toFixed(0)}</span>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-sm font-bold">
                      {s.score.toFixed(0)}
                    </div>
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-6 flex-1 text-[10px]"
                    disabled={attributeMutation.isPending}
                    onClick={async () => {
                      try {
                        await attributeMutation.mutateAsync({
                          kit_id: s.kit_id,
                          entity_type: entityType,
                          entity_id: entityId,
                          confidence: "suspected",
                          evidence_snapshot: s.signals,
                        });
                        toast.success(`Linked kit to ${entityName}`);
                      } catch (e) {
                        toast.error(
                          `Link failed: ${(e as Error).message}`,
                        );
                      }
                    }}
                  >
                    <Plus className="h-3 w-3 mr-1" />
                    Link (suspected)
                  </Button>
                  <Link to={`/phish-match/${s.kit_id}`}>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 px-1"
                      title="Open PhishMatch for this kit"
                    >
                      <ExternalLink className="h-3 w-3" />
                    </Button>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

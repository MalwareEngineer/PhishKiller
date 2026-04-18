import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  usePhishMatchForKit,
  useAttributeKit,
  useUnattributeKit,
} from "@/hooks/use-phishmatch";
import { useKit } from "@/hooks/use-kits";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Progress } from "@/components/ui/progress";
import {
  ArrowLeft,
  CheckCircle2,
  HelpCircle,
  Sparkles,
  Users,
  Target,
  Layers,
  ExternalLink,
  Info,
} from "lucide-react";
import { toast } from "sonner";
import type {
  PhishMatchCandidate,
  PhishMatchEntityType,
  PhishMatchSignals,
} from "@/lib/api";

const ENTITY_META: Record<
  PhishMatchEntityType,
  { label: string; plural: string; icon: typeof Users; route: string }
> = {
  actor: { label: "Actor", plural: "Actors", icon: Users, route: "actors" },
  family: { label: "Family", plural: "Families", icon: Layers, route: "families" },
  campaign: { label: "Campaign", plural: "Campaigns", icon: Target, route: "campaigns" },
};

function SignalBar({ label, value, cap }: { label: string; value: number; cap: number }) {
  const pct = cap > 0 ? Math.min(100, (value / cap) * 100) : 0;
  const dimmed = value <= 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className={dimmed ? "text-muted-foreground" : "font-medium"}>
          {label}
        </span>
        <span className={dimmed ? "text-muted-foreground" : "font-mono"}>
          {value.toFixed(1)}
          <span className="text-muted-foreground"> / {cap}</span>
        </span>
      </div>
      <Progress value={pct} className="h-1.5" />
    </div>
  );
}

function EvidenceDetail({ signals }: { signals: PhishMatchSignals }) {
  const { evidence } = signals;
  const hasAny =
    evidence.tlsh.length > 0 ||
    evidence.ioc.length > 0 ||
    evidence.yara.length > 0 ||
    evidence.source_url.length > 0 ||
    evidence.redirect.length > 0;

  if (!hasAny) {
    return (
      <p className="text-xs text-muted-foreground italic">
        No supporting evidence captured (signals aggregated to zero).
      </p>
    );
  }

  return (
    <div className="space-y-3 text-xs">
      {evidence.tlsh.length > 0 && (
        <div>
          <div className="mb-1 font-medium">TLSH neighbours</div>
          <div className="space-y-1">
            {evidence.tlsh.map((t) => (
              <div
                key={t.kit_id}
                className="flex items-center justify-between rounded bg-muted/30 px-2 py-1 font-mono"
              >
                <Link
                  to={`/kits/${t.kit_id}`}
                  className="text-blue-400 hover:underline"
                >
                  {t.kit_id.slice(0, 8)}…
                </Link>
                <span className="text-muted-foreground">dist={t.distance}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {evidence.ioc.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Shared indicators</div>
          <div className="space-y-1">
            {evidence.ioc.map((i, idx) => (
              <div
                key={`${i.type}-${i.value}-${idx}`}
                className="flex items-center gap-2 rounded bg-muted/30 px-2 py-1"
              >
                <Badge variant="outline" className="text-[10px] uppercase">
                  {i.type}
                </Badge>
                <span className="truncate font-mono" title={i.value}>
                  {i.value}
                </span>
                <span className="ml-auto text-muted-foreground">
                  +{i.weight}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {evidence.yara.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Shared YARA rules</div>
          <div className="flex flex-wrap gap-1">
            {evidence.yara.map((r) => (
              <Link
                key={r}
                to={`/kits?search=${encodeURIComponent(`yara:${r}`)}`}
              >
                <Badge
                  variant="default"
                  className="cursor-pointer font-mono text-[10px]"
                >
                  {r}
                </Badge>
              </Link>
            ))}
          </div>
        </div>
      )}

      {evidence.source_url.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Shared source domain</div>
          <div className="flex flex-wrap gap-1">
            {evidence.source_url.map((d) => (
              <Badge key={d} variant="outline" className="font-mono text-[10px]">
                {d}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {evidence.redirect.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Shared redirect hosts</div>
          <div className="flex flex-wrap gap-1">
            {evidence.redirect.map((d) => (
              <Badge key={d} variant="outline" className="font-mono text-[10px]">
                {d}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CandidateCard({
  kitId,
  candidate,
  onAttribute,
  attributing,
}: {
  kitId: string;
  candidate: PhishMatchCandidate;
  onAttribute: (confidence: "verified" | "suspected") => void;
  attributing: boolean;
}) {
  const meta = ENTITY_META[candidate.entity_type];
  const Icon = meta.icon;

  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start gap-3">
          <div className="rounded bg-muted p-2">
            <Icon className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <Link
                to={`/${meta.route}/${candidate.entity_id}`}
                className="truncate text-sm font-semibold text-blue-400 hover:underline"
                title={candidate.entity_name}
              >
                {candidate.entity_name}
              </Link>
              {candidate.auto_generated && (
                <Badge variant="outline" className="text-[10px]">
                  auto-generated
                </Badge>
              )}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {candidate.supporting_kit_ids.length} supporting kit
              {candidate.supporting_kit_ids.length === 1 ? "" : "s"}
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-2xl font-bold">
              {candidate.score.toFixed(0)}
            </div>
            <div className="text-[10px] uppercase text-muted-foreground">
              score
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <SignalBar label="TLSH" value={candidate.signals.tlsh} cap={40} />
          <SignalBar label="IOC" value={candidate.signals.ioc} cap={40} />
          <SignalBar label="YARA" value={candidate.signals.yara} cap={15} />
          <SignalBar label="URL" value={candidate.signals.source_url} cap={10} />
          <SignalBar
            label="Redir"
            value={candidate.signals.redirect_chain}
            cap={10}
          />
        </div>

        <Accordion className="w-full">
          <AccordionItem value="evidence" className="border-b-0">
            <AccordionTrigger className="py-2 text-xs hover:no-underline">
              <span className="flex items-center gap-1 text-muted-foreground">
                <Info className="h-3 w-3" />
                View evidence
              </span>
            </AccordionTrigger>
            <AccordionContent>
              <EvidenceDetail signals={candidate.signals} />
            </AccordionContent>
          </AccordionItem>
        </Accordion>

        <div className="flex gap-2 pt-2">
          <Button
            size="sm"
            variant="default"
            disabled={attributing}
            onClick={() => onAttribute("verified")}
            className="flex-1"
          >
            <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
            Attribute (verified)
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={attributing}
            onClick={() => onAttribute("suspected")}
            className="flex-1"
          >
            <HelpCircle className="h-3.5 w-3.5 mr-1" />
            Suspected
          </Button>
          <Link to={`/${meta.route}/${candidate.entity_id}`}>
            <Button
              size="sm"
              variant="ghost"
              title={`Open ${meta.label}`}
            >
              <ExternalLink className="h-3.5 w-3.5" />
            </Button>
          </Link>
        </div>

        <div className="hidden">{kitId}</div>
      </CardContent>
    </Card>
  );
}

function EmptyPanel({
  entityType,
  reason,
}: {
  entityType: PhishMatchEntityType;
  reason: string | null;
}) {
  const meta = ENTITY_META[entityType];
  return (
    <Card>
      <CardContent className="py-8 text-center text-sm text-muted-foreground">
        <Sparkles className="mx-auto mb-2 h-5 w-5 opacity-50" />
        <div>No close {meta.plural.toLowerCase()} matched this kit.</div>
        {reason && <div className="mt-1 text-xs italic">Reason: {reason}</div>}
      </CardContent>
    </Card>
  );
}

export function PhishMatchPage() {
  const { kitId } = useParams<{ kitId: string }>();
  const { data: kit, isLoading: kitLoading } = useKit(kitId ?? "");
  const { data, isLoading, error } = usePhishMatchForKit(kitId);
  const attributeMutation = useAttributeKit();
  const unattributeMutation = useUnattributeKit();
  const [tab, setTab] = useState<PhishMatchEntityType>("actor");

  if (!kitId) {
    return <div className="p-8 text-red-400">Missing kit id.</div>;
  }
  if (kitLoading || isLoading) return <PageLoading />;
  if (error) {
    return (
      <div className="p-8 text-red-400">
        Error loading PhishMatch: {(error as Error).message}
      </div>
    );
  }
  if (!data || !kit) {
    return <div className="p-8 text-muted-foreground">No data.</div>;
  }

  const handleAttribute = async (
    candidate: PhishMatchCandidate,
    confidence: "verified" | "suspected",
  ) => {
    try {
      await attributeMutation.mutateAsync({
        kit_id: kitId,
        entity_type: candidate.entity_type,
        entity_id: candidate.entity_id,
        confidence,
        evidence_snapshot: candidate.signals,
      });
      toast.success(
        `Attributed to ${candidate.entity_name} (${confidence})`,
      );
    } catch (e) {
      toast.error(`Attribute failed: ${(e as Error).message}`);
    }
  };

  const attributed = {
    actor: new Set((kit.actors ?? []).map((a: { id: string }) => a.id)),
    family: new Set((kit.families ?? []).map((f: { id: string }) => f.id)),
    campaign: new Set((kit.campaigns ?? []).map((c: { id: string }) => c.id)),
  } as Record<PhishMatchEntityType, Set<string>>;

  const filterPool = (list: PhishMatchCandidate[], type: PhishMatchEntityType) =>
    list.filter((c) => !attributed[type].has(c.entity_id));

  const actorCandidates = filterPool(data.actors, "actor");
  const familyCandidates = filterPool(data.families, "family");
  const campaignCandidates = filterPool(data.campaigns, "campaign");

  const totalCandidates =
    actorCandidates.length + familyCandidates.length + campaignCandidates.length;

  const existingLinks: Array<{
    type: PhishMatchEntityType;
    id: string;
    name: string;
  }> = [
    ...(kit.actors ?? []).map((a: { id: string; name: string }) => ({
      type: "actor" as const,
      id: a.id,
      name: a.name,
    })),
    ...(kit.families ?? []).map((f: { id: string; name: string }) => ({
      type: "family" as const,
      id: f.id,
      name: f.name,
    })),
    ...(kit.campaigns ?? []).map((c: { id: string; name: string }) => ({
      type: "campaign" as const,
      id: c.id,
      name: c.name,
    })),
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Link to={`/kits/${kitId}`}>
          <Button size="sm" variant="ghost">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to kit
          </Button>
        </Link>
        <h1 className="text-2xl font-bold">PhishMatch</h1>
      </div>

      <Card>
        <CardContent className="p-4 space-y-2">
          <div className="flex items-center gap-2">
            <div className="text-sm text-muted-foreground">Subject kit</div>
            <Link
              to={`/kits/${kitId}`}
              className="font-mono text-sm text-blue-400 hover:underline"
            >
              {kitId.slice(0, 8)}…
            </Link>
            <Badge variant="outline" className="truncate text-xs max-w-md">
              {kit.source_url}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Candidate entities ranked by composite similarity to kits already
            attributed to that entity. Scores below{" "}
            <span className="font-mono">{data.min_surface_score}</span> are
            hidden. Attribute using the buttons on each card — the evidence
            snapshot is stored on the link for audit.
          </p>
        </CardContent>
      </Card>

      {existingLinks.length > 0 && (
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="text-xs font-medium text-muted-foreground uppercase">
              Already attributed
            </div>
            <div className="flex flex-wrap gap-2">
              {existingLinks.map((l) => {
                const meta = ENTITY_META[l.type];
                return (
                  <div
                    key={`${l.type}-${l.id}`}
                    className="flex items-center gap-1 rounded border px-2 py-1 text-xs"
                  >
                    <Badge variant="secondary" className="text-[10px]">
                      {meta.label}
                    </Badge>
                    <Link
                      to={`/${meta.route}/${l.id}`}
                      className="text-blue-400 hover:underline"
                    >
                      {l.name}
                    </Link>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="ml-1 h-5 px-1 text-[10px]"
                      disabled={unattributeMutation.isPending}
                      onClick={async () => {
                        try {
                          await unattributeMutation.mutateAsync({
                            kit_id: kitId,
                            entity_type: l.type,
                            entity_id: l.id,
                          });
                          toast.success(`Removed link to ${l.name}`);
                        } catch (e) {
                          toast.error(`Remove failed: ${(e as Error).message}`);
                        }
                      }}
                    >
                      unlink
                    </Button>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {totalCandidates === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Sparkles className="mx-auto mb-3 h-8 w-8 text-muted-foreground opacity-50" />
            <div className="text-lg font-medium">No close matches</div>
            <p className="mt-1 text-sm text-muted-foreground">
              {data.no_matches_reason
                ? `(${data.no_matches_reason})`
                : "Nothing scored above the surfacing threshold."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Tabs value={tab} onValueChange={(v) => setTab(v as PhishMatchEntityType)}>
          <TabsList>
            <TabsTrigger value="actor">
              Actors ({actorCandidates.length})
            </TabsTrigger>
            <TabsTrigger value="family">
              Families ({familyCandidates.length})
            </TabsTrigger>
            <TabsTrigger value="campaign">
              Campaigns ({campaignCandidates.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="actor" className="mt-4 space-y-3">
            {actorCandidates.length === 0 ? (
              <EmptyPanel entityType="actor" reason={data.no_matches_reason} />
            ) : (
              actorCandidates.map((c) => (
                <CandidateCard
                  key={c.entity_id}
                  kitId={kitId}
                  candidate={c}
                  attributing={attributeMutation.isPending}
                  onAttribute={(conf) => handleAttribute(c, conf)}
                />
              ))
            )}
          </TabsContent>

          <TabsContent value="family" className="mt-4 space-y-3">
            {familyCandidates.length === 0 ? (
              <EmptyPanel entityType="family" reason={data.no_matches_reason} />
            ) : (
              familyCandidates.map((c) => (
                <CandidateCard
                  key={c.entity_id}
                  kitId={kitId}
                  candidate={c}
                  attributing={attributeMutation.isPending}
                  onAttribute={(conf) => handleAttribute(c, conf)}
                />
              ))
            )}
          </TabsContent>

          <TabsContent value="campaign" className="mt-4 space-y-3">
            {campaignCandidates.length === 0 ? (
              <EmptyPanel entityType="campaign" reason={data.no_matches_reason} />
            ) : (
              campaignCandidates.map((c) => (
                <CandidateCard
                  key={c.entity_id}
                  kitId={kitId}
                  candidate={c}
                  attributing={attributeMutation.isPending}
                  onAttribute={(conf) => handleAttribute(c, conf)}
                />
              ))
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}

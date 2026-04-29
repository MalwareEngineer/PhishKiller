import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Activity,
  CalendarClock,
  FileSearch,
  Fingerprint,
  GitBranch,
  Layers,
  Package,
  Search,
  Shapes,
  Target,
  Trash2,
  TrendingUp,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  useDeleteFamily,
  useFamily,
  useFamilyActors,
  useFamilyCampaigns,
  useFamilyIndicators,
  useFamilyKits,
  useFamilyStats,
  useFamilyYaraRules,
  useUpdateFamily,
} from "@/hooks/use-families";
import { EditableChips } from "@/components/shared/editable-chips";
import { EditableDescription } from "@/components/shared/editable-description";
import { EditableText } from "@/components/shared/editable-text";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { IocTypeBadge } from "@/components/shared/ioc-type-badge";
import { Pagination } from "@/components/shared/pagination";
import { PageLoading, TableLoading } from "@/components/shared/loading";
import { SuggestedKitsPanel } from "@/components/shared/suggested-kits-panel";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const KITS_PAGE_SIZE = 25;
const INDICATORS_PAGE_SIZE = 25;

function formatDateOnly(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Header — name (editable), delete
// ---------------------------------------------------------------------------

function FamilyHeader({
  id,
  name,
  onUpdate,
  onDelete,
  isUpdating,
  isDeleting,
}: {
  id: string;
  name: string;
  onUpdate: (next: string) => void;
  onDelete: () => void;
  isUpdating: boolean;
  isDeleting: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4 flex-wrap">
      <div className="space-y-2 min-w-0">
        <div className="flex items-center gap-2">
          <Layers className="h-6 w-6 text-muted-foreground shrink-0" />
          <EditableText
            value={name}
            onSave={onUpdate}
            isPending={isUpdating}
            displayClassName="text-2xl font-bold tracking-tight"
            allowEmpty={false}
            placeholder="Family name"
          />
        </div>
        <p className="text-xs text-muted-foreground font-mono">{id}</p>
      </div>
      <Button
        variant="destructive"
        size="sm"
        onClick={onDelete}
        disabled={isDeleting}
      >
        <Trash2 className="h-4 w-4 mr-1" />
        {isDeleting ? "Deleting…" : "Delete"}
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview tab
// ---------------------------------------------------------------------------

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: typeof Users;
  label: string;
  value: number | string;
  hint?: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Icon className="h-3.5 w-3.5" />
          {label}
        </div>
        <div className="text-2xl font-bold mt-1">{value}</div>
        {hint && (
          <div className="text-[10px] text-muted-foreground mt-0.5">{hint}</div>
        )}
      </CardContent>
    </Card>
  );
}

function OverviewTab({ id }: { id: string }) {
  const { data: stats, isLoading } = useFamilyStats(id);

  if (isLoading || !stats) return <TableLoading />;

  // Polymorphism reading — what fraction of kits are unique binaries?
  // Low ratio = repackaging the same file; high ratio = each deploy
  // is a fresh build.  Useful for the operator to know at a glance
  // whether de-duplication on hash will catch this family.
  const sha256Ratio =
    stats.kit_count === 0
      ? 0
      : Math.round((stats.distinct_sha256_count / stats.kit_count) * 100);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 grid-cols-2 md:grid-cols-4">
        <StatCard icon={Package} label="Kits" value={stats.kit_count} />
        <StatCard
          icon={Users}
          label="Curated actors"
          value={stats.actor_count}
          hint="family ↔ actor links"
        />
        <StatCard icon={Target} label="Campaigns" value={stats.campaign_count} />
        <StatCard
          icon={Search}
          label="Indicators"
          value={stats.indicator_count}
        />
      </div>

      {/* Polymorphism row — distinct hashes vs kit count */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Fingerprint className="h-4 w-4" />
            Polymorphism
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-3">
          <div>
            <span className="text-xs text-muted-foreground">
              Distinct SHA256
            </span>
            <p className="text-lg font-semibold mt-1">
              {stats.distinct_sha256_count}
              <span className="text-xs text-muted-foreground font-normal ml-2">
                / {stats.kit_count} kits ({sha256Ratio}%)
              </span>
            </p>
            <p className="text-[11px] text-muted-foreground mt-1">
              Low ratio = same file repackaged across deploys.
            </p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">
              Distinct TLSH clusters
            </span>
            <p className="text-lg font-semibold mt-1">
              {stats.distinct_tlsh_count}
            </p>
            <p className="text-[11px] text-muted-foreground mt-1">
              Near-duplicate fuzzy-hash buckets.
            </p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              Active window
            </span>
            <p className="text-sm mt-1">
              {formatDateOnly(stats.first_seen_computed)} →{" "}
              {formatDateOnly(stats.last_seen_computed)}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Activity-over-time bar chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            Activity over time
          </CardTitle>
        </CardHeader>
        <CardContent>
          {stats.timeline.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4">
              No kit activity recorded yet.
            </p>
          ) : (
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.timeline}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    className="stroke-muted"
                  />
                  <XAxis
                    dataKey="month"
                    fontSize={11}
                    className="text-muted-foreground"
                  />
                  <YAxis
                    fontSize={11}
                    allowDecimals={false}
                    className="text-muted-foreground"
                  />
                  <Tooltip
                    cursor={{ fill: "hsl(var(--muted))", opacity: 0.3 }}
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      fontSize: 12,
                    }}
                  />
                  <Bar
                    dataKey="count"
                    fill="hsl(var(--primary))"
                    className="fill-emerald-500"
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Target brand mix */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Target className="h-4 w-4" />
              Target brands
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.target_brand_distribution.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No campaign brand data yet.
              </p>
            ) : (
              <DistributionBars
                items={stats.target_brand_distribution.map((b) => ({
                  label: b.brand,
                  count: b.count,
                  href: undefined,
                }))}
              />
            )}
          </CardContent>
        </Card>

        {/* Top deploying actors */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Users className="h-4 w-4" />
              Top deploying actors
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.top_actors.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No actor attributions on this family's kits yet.
              </p>
            ) : (
              <DistributionBars
                items={stats.top_actors.map((a) => ({
                  label: a.actor_name,
                  count: a.count,
                  href: `/actors/${a.actor_id}`,
                }))}
              />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top YARA rules anchoring this family */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <FileSearch className="h-4 w-4" />
            Top YARA rules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {stats.top_yara_rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No YARA matches across this family's kits.
            </p>
          ) : (
            <DistributionBars
              items={stats.top_yara_rules.map((r) => ({
                label: r.rule,
                count: r.count,
                href: `/kits?yara_rule=${encodeURIComponent(r.rule)}`,
              }))}
            />
          )}
        </CardContent>
      </Card>

      {/* Top indicators panel */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Search className="h-4 w-4" />
            Top indicators
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {stats.top_indicators.length === 0 ? (
            <p className="text-sm text-muted-foreground p-4">
              No indicators across this family's kits yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead className="text-right">Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stats.top_indicators.map((ind, idx) => (
                  <TableRow key={`${ind.type}-${ind.value}-${idx}`}>
                    <TableCell>
                      <IocTypeBadge type={ind.type as never} />
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-md truncate">
                      {ind.value}
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {ind.count}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// Tiny horizontal-bar visualization — same impl as actor-detail.  Not
// extracted to a shared component because the two pages are still
// stabilizing; once campaign-detail (PR 5) lands a third copy we'll
// promote it.
function DistributionBars({
  items,
}: {
  items: { label: string; count: number; href: string | undefined }[];
}) {
  const max = Math.max(...items.map((i) => i.count));
  return (
    <div className="space-y-2">
      {items.map((it) => {
        const labelEl = (
          <span className="truncate text-sm" title={it.label}>
            {it.label}
          </span>
        );
        return (
          <div key={it.label} className="flex items-center gap-3 text-sm">
            <div className="w-32 shrink-0 text-muted-foreground hover:text-foreground">
              {it.href ? (
                <Link to={it.href} className="hover:underline">
                  {labelEl}
                </Link>
              ) : (
                labelEl
              )}
            </div>
            <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full bg-emerald-500/80 transition-all"
                style={{ width: `${(it.count / max) * 100}%` }}
              />
            </div>
            <span className="w-10 text-right font-mono text-xs">
              {it.count}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Identity tab — operator-editable description + aliases
// ---------------------------------------------------------------------------

function IdentityTab({
  id,
  description,
  aliases,
  onUpdate,
  isUpdating,
}: {
  id: string;
  description: string | null | undefined;
  aliases: string[] | null | undefined;
  onUpdate: (data: Record<string, unknown>) => void;
  isUpdating: boolean;
}) {
  return (
    <div className="space-y-4">
      <EditableDescription
        value={description}
        onSave={(d) => onUpdate({ description: d })}
        isPending={isUpdating}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Aliases</CardTitle>
        </CardHeader>
        <CardContent>
          <EditableChips
            label=""
            value={aliases}
            onSave={(v) => onUpdate({ aliases: v })}
            isPending={isUpdating}
            placeholder="Tycoon2FA, Sneaky2FA, …"
            emptyText="No aliases"
          />
        </CardContent>
      </Card>

      <SuggestedKitsPanel entityType="family" entityId={id} entityName="" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Kits tab — paginated, click-through
// ---------------------------------------------------------------------------

function KitsTab({ id }: { id: string }) {
  const [offset, setOffset] = useState(0);
  const { data, isLoading } = useFamilyKits(id, {
    offset,
    limit: KITS_PAGE_SIZE,
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">
          Kits attributed to this family
          {data && (
            <span className="text-xs text-muted-foreground font-normal ml-2">
              ({data.total})
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="p-4">
            <TableLoading />
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Source URL</TableHead>
                <TableHead>SHA256</TableHead>
                <TableHead>TLSH</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.items ?? []).map((kit) => (
                <TableRow key={kit.id} className="cursor-pointer hover:bg-muted/40">
                  <TableCell>
                    <KitStatusBadge status={kit.status} />
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    <Link to={`/kits/${kit.id}`} className="hover:underline">
                      {kit.source_url}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {kit.sha256?.slice(0, 12) ?? "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {kit.tlsh?.slice(0, 12) ?? "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(kit.created_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
              {data && data.items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-center text-muted-foreground py-8"
                  >
                    No kits attributed to this family yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
      {data && data.total > KITS_PAGE_SIZE && (
        <div className="p-3">
          <Pagination
            offset={offset}
            limit={KITS_PAGE_SIZE}
            total={data.total}
            onOffsetChange={setOffset}
          />
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// YARA-rules tab — flat list, not paginated (rare > 30 distinct)
// ---------------------------------------------------------------------------

function YaraTab({ id }: { id: string }) {
  const { data, isLoading } = useFamilyYaraRules(id);
  if (isLoading) return <TableLoading />;
  if (!data || data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground p-4">
        No YARA rule matches across this family's kits yet.
      </p>
    );
  }
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">
          YARA rules anchoring this family
          <span className="text-xs text-muted-foreground font-normal ml-2">
            ({data.length})
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Rule</TableHead>
              <TableHead className="text-right">Kits matched</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((r) => (
              <TableRow key={r.rule}>
                <TableCell className="font-mono text-xs">
                  <Link
                    to={`/kits?yara_rule=${encodeURIComponent(r.rule)}`}
                    className="hover:underline"
                  >
                    {r.rule}
                  </Link>
                </TableCell>
                <TableCell className="text-right font-mono">{r.count}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Indicators tab — paginated
// ---------------------------------------------------------------------------

function IndicatorsTab({ id }: { id: string }) {
  const [offset, setOffset] = useState(0);
  const { data, isLoading } = useFamilyIndicators(
    id, offset, INDICATORS_PAGE_SIZE,
  );

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">
          Indicators across family kits
          {data && (
            <span className="text-xs text-muted-foreground font-normal ml-2">
              ({data.total})
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="p-4">
            <TableLoading />
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.items ?? []).map((ind) => (
                <TableRow key={ind.id}>
                  <TableCell>
                    <IocTypeBadge type={ind.type as never} />
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    {ind.value}
                  </TableCell>
                  <TableCell className="text-xs">{ind.confidence}</TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(ind.created_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
              {data && data.items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="text-center text-muted-foreground py-8"
                  >
                    No indicators across this family's kits yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
      {data && data.total > INDICATORS_PAGE_SIZE && (
        <div className="p-3">
          <Pagination
            offset={offset}
            limit={INDICATORS_PAGE_SIZE}
            total={data.total}
            onOffsetChange={setOffset}
          />
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Actors + Campaigns tabs — flat lists with click-through
// ---------------------------------------------------------------------------

function ActorsTab({ id }: { id: string }) {
  const { data, isLoading } = useFamilyActors(id);
  if (isLoading) return <TableLoading />;
  if (!data || data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground p-4">
        No actors curated as members of this family.
      </p>
    );
  }
  return (
    <Card>
      <CardContent className="p-4 flex flex-wrap gap-2">
        {data.map((a) => (
          <Link key={a.id} to={`/actors/${a.id}`}>
            <Badge
              variant="outline"
              className="cursor-pointer hover:bg-muted text-sm py-1"
            >
              <Users className="h-3 w-3 mr-1" />
              {a.name}
            </Badge>
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}

function CampaignsTab({ id }: { id: string }) {
  const { data, isLoading } = useFamilyCampaigns(id);
  if (isLoading) return <TableLoading />;
  if (!data || data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground p-4">
        No campaigns share kits with this family yet.
      </p>
    );
  }
  return (
    <Card>
      <CardContent className="p-4 flex flex-wrap gap-2">
        {data.map((c) => (
          <Link key={c.id} to={`/campaigns/${c.id}`}>
            <Badge
              variant="outline"
              className="cursor-pointer hover:bg-muted text-sm py-1"
            >
              <GitBranch className="h-3 w-3 mr-1" />
              {c.name}
              {c.target_brand && (
                <span className="text-muted-foreground ml-1">
                  ({c.target_brand})
                </span>
              )}
            </Badge>
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function FamilyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: family, isLoading } = useFamily(id!);
  const updateMutation = useUpdateFamily();
  const deleteMutation = useDeleteFamily();

  if (isLoading || !family || !id) return <PageLoading />;

  const handleUpdate = (data: Record<string, unknown>) => {
    updateMutation.mutate(
      { id, ...data },
      {
        onSuccess: () => toast.success("Saved"),
        onError: (err) => toast.error(err.message),
      },
    );
  };

  const handleDelete = () => {
    if (
      !window.confirm(
        `Delete family "${family.name}"? Linked kits will be unlinked but not deleted.`,
      )
    )
      return;
    deleteMutation.mutate(id, { onSuccess: () => navigate("/families") });
  };

  return (
    <div className="space-y-6">
      <FamilyHeader
        id={id}
        name={family.name}
        onUpdate={(name) => handleUpdate({ name })}
        onDelete={handleDelete}
        isUpdating={updateMutation.isPending}
        isDeleting={deleteMutation.isPending}
      />

      <Tabs defaultValue="overview">
        <TabsList className="overflow-x-auto overflow-y-hidden">
          <TabsTrigger value="overview">
            <Activity className="h-3.5 w-3.5 mr-1.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="identity">
            <Shapes className="h-3.5 w-3.5 mr-1.5" />
            Identity
          </TabsTrigger>
          <TabsTrigger value="kits">
            <Package className="h-3.5 w-3.5 mr-1.5" />
            Kits
          </TabsTrigger>
          <TabsTrigger value="yara">
            <FileSearch className="h-3.5 w-3.5 mr-1.5" />
            YARA
          </TabsTrigger>
          <TabsTrigger value="indicators">
            <Search className="h-3.5 w-3.5 mr-1.5" />
            Indicators
          </TabsTrigger>
          <TabsTrigger value="actors">
            <Users className="h-3.5 w-3.5 mr-1.5" />
            Actors
          </TabsTrigger>
          <TabsTrigger value="campaigns">
            <Target className="h-3.5 w-3.5 mr-1.5" />
            Campaigns
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab id={id} />
        </TabsContent>
        <TabsContent value="identity" className="mt-4">
          <IdentityTab
            id={id}
            description={family.description}
            aliases={family.aliases}
            onUpdate={handleUpdate}
            isUpdating={updateMutation.isPending}
          />
        </TabsContent>
        <TabsContent value="kits" className="mt-4">
          <KitsTab id={id} />
        </TabsContent>
        <TabsContent value="yara" className="mt-4">
          <YaraTab id={id} />
        </TabsContent>
        <TabsContent value="indicators" className="mt-4">
          <IndicatorsTab id={id} />
        </TabsContent>
        <TabsContent value="actors" className="mt-4">
          <ActorsTab id={id} />
        </TabsContent>
        <TabsContent value="campaigns" className="mt-4">
          <CampaignsTab id={id} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

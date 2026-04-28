import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Fingerprint, Plus, Trash2, Globe, AlertCircle } from "lucide-react";
import { toast } from "sonner";

import { useVictims } from "@/hooks/use-victims";
import {
  useCreateMonitoredDomain,
  useDeleteMonitoredDomain,
  useMonitoredDomains,
} from "@/hooks/use-monitored-domains";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { VictimType } from "@/types/api";

const PAGE_SIZE = 25;
const ALL = "__all__";

const TYPE_LABEL: Record<VictimType, string> = {
  user: "User",
  exec: "Exec",
  distro: "Distro",
  shared_mailbox: "Shared mailbox",
  service: "Service",
  unknown: "Unknown",
};

const TYPE_BADGE_VARIANT: Record<VictimType, "default" | "secondary" | "outline" | "destructive"> = {
  user: "secondary",
  exec: "destructive",
  distro: "outline",
  shared_mailbox: "outline",
  service: "outline",
  unknown: "outline",
};

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = now - then;
  const days = Math.floor(diff / 86400000);
  if (days >= 30) return `${Math.floor(days / 30)}mo ago`;
  if (days >= 1) return `${days}d ago`;
  const hours = Math.floor(diff / 3600000);
  if (hours >= 1) return `${hours}h ago`;
  const mins = Math.floor(diff / 60000);
  if (mins >= 1) return `${mins}m ago`;
  return "just now";
}

// ---------------------------------------------------------------------------
// Monitored-domain admin block — gates Victim creation, so it deserves
// prominent placement at the top of the page rather than hidden in a
// separate route.  Inline list + add form covers the day-to-day flow
// (add a subsidiary domain, see the resulting victims appear).
// ---------------------------------------------------------------------------

function MonitoredDomainsBlock() {
  const { data, isLoading } = useMonitoredDomains(0, 200);
  const create = useCreateMonitoredDomain();
  const remove = useDeleteMonitoredDomain();

  const [newDomain, setNewDomain] = useState("");
  const [newDescription, setNewDescription] = useState("");

  const handleAdd = () => {
    const domain = newDomain.trim().toLowerCase();
    if (!domain) return;
    create.mutate(
      {
        domain,
        description: newDescription.trim() || undefined,
      },
      {
        onSuccess: () => {
          toast.success(`Added ${domain} to monitored domains`);
          setNewDomain("");
          setNewDescription("");
        },
        onError: (err) => toast.error(err.message),
      },
    );
  };

  const handleDelete = (id: string, domain: string) => {
    if (
      !window.confirm(
        `Stop monitoring "${domain}"?  Existing Victim rows for this domain ` +
          `will remain (so historical attack-surface data isn't lost), but ` +
          `new observations of those addresses will no longer create new ` +
          `Victim entries.`,
      )
    ) {
      return;
    }
    remove.mutate(id, {
      onSuccess: () => toast.success(`Removed ${domain}`),
      onError: (err) => toast.error(err.message),
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Globe className="h-4 w-4" />
          Monitored domains
          {data && (
            <span className="text-xs text-muted-foreground font-normal">
              ({data.total})
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Allowlist that gates Victim entity creation. Suffix-aware:
          adding <code className="font-mono text-foreground">acme.com</code>
          {" "}covers <code className="font-mono text-foreground">user@sub.acme.com</code>
          {" "}but not <code className="font-mono text-foreground">user@acme-hr.com</code>.
          Subsidiaries that don't share the parent need their own row.
          Observed emails on non-monitored domains stay tracked as
          Indicators (full IOC search) but don't become Victims.
        </p>

        <div className="flex gap-2">
          <Input
            placeholder="acme.com"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleAdd();
            }}
            className="max-w-[14rem] font-mono text-sm"
          />
          <Input
            placeholder="Description (optional)"
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleAdd();
            }}
            className="flex-1"
          />
          <Button
            size="sm"
            onClick={handleAdd}
            disabled={!newDomain.trim() || create.isPending}
          >
            <Plus className="mr-1 h-4 w-4" />
            {create.isPending ? "Adding…" : "Add"}
          </Button>
        </div>

        {isLoading ? (
          <TableLoading />
        ) : data && data.items.length > 0 ? (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead className="w-24"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono text-sm">{d.domain}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {d.description || "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 px-2 text-destructive hover:bg-destructive/10 hover:text-destructive"
                        onClick={() => handleDelete(d.id, d.domain)}
                        disabled={remove.isPending}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            No domains monitored yet. Add one above to start promoting
            observed emails on that domain to Victim entities.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Victims block — paginated, filter-driven table.  The whole point of
// the page; everything else supports this view.
// ---------------------------------------------------------------------------

export function PhishPrintPage() {
  const [offset, setOffset] = useState(0);
  const [domainFilter, setDomainFilter] = useState<string>(ALL);
  const [typeFilter, setTypeFilter] = useState<string>(ALL);
  const [search, setSearch] = useState("");

  const { data: domainsData } = useMonitoredDomains(0, 200);
  const { data, isLoading } = useVictims({
    offset,
    limit: PAGE_SIZE,
    domain: domainFilter === ALL ? undefined : domainFilter,
    type: typeFilter === ALL ? undefined : (typeFilter as VictimType),
    search: search.trim() || undefined,
  });

  const noDomainsMonitored = useMemo(
    () => (domainsData?.items.length ?? 0) === 0,
    [domainsData],
  );

  const renderDomainName = (value: string | null) => {
    if (!value || value === ALL) return "All domains";
    return value;
  };

  const renderTypeName = (value: string | null) => {
    if (!value || value === ALL) return "All types";
    return TYPE_LABEL[value as VictimType] ?? value;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Fingerprint className="h-6 w-6" />
          PhishPrint
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Per-employee attack-surface footprint. Every email observed
          across the analysis pipeline whose domain is on the
          monitored allowlist below shows up here as a tracked
          victim, with the full per-kit observation history reachable
          via the row drill-down.
        </p>
      </div>

      <MonitoredDomainsBlock />

      {noDomainsMonitored && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-4 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-amber-500 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-medium text-amber-700 dark:text-amber-300">
              No monitored domains configured.
            </p>
            <p className="text-muted-foreground mt-1">
              Until at least one domain is added above, the analysis
              pipeline won't promote any observed emails to Victim
              entities — the table below will stay empty even as kits
              flow through. Non-monitored emails are still recorded
              as Indicator rows on each kit.
            </p>
          </div>
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <CardTitle className="text-sm font-medium">
              Victims
              {data && (
                <span className="text-xs text-muted-foreground font-normal ml-2">
                  ({data.total})
                </span>
              )}
            </CardTitle>
            <div className="flex items-center gap-2 flex-wrap">
              <Input
                placeholder="Search email or name…"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setOffset(0);
                }}
                className="w-64"
              />
              <Select
                value={domainFilter}
                onValueChange={(v) => {
                  setDomainFilter(v ?? ALL);
                  setOffset(0);
                }}
              >
                <SelectTrigger className="w-44">
                  <SelectValue placeholder="All domains">
                    {renderDomainName}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All domains</SelectItem>
                  {(domainsData?.items ?? []).map((d) => (
                    <SelectItem key={d.id} value={d.domain}>
                      {d.domain}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select
                value={typeFilter}
                onValueChange={(v) => {
                  setTypeFilter(v ?? ALL);
                  setOffset(0);
                }}
              >
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="All types">
                    {renderTypeName}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All types</SelectItem>
                  {(Object.keys(TYPE_LABEL) as VictimType[]).map((t) => (
                    <SelectItem key={t} value={t}>
                      {TYPE_LABEL[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
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
                  <TableHead>Email</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Domain</TableHead>
                  <TableHead>First seen</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((v) => (
                  <TableRow key={v.id} className="cursor-pointer hover:bg-muted/40">
                    <TableCell>
                      <Link
                        to={`/phishprint/victims/${v.id}`}
                        className="block"
                      >
                        <div className="font-medium font-mono text-sm">
                          {v.email}
                        </div>
                        {v.display_name && (
                          <div className="text-xs text-muted-foreground">
                            {v.display_name}
                          </div>
                        )}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant={TYPE_BADGE_VARIANT[v.type]}>
                        {TYPE_LABEL[v.type]}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {v.domain}
                    </TableCell>
                    <TableCell
                      className="text-xs text-muted-foreground"
                      title={v.first_seen ?? undefined}
                    >
                      {relativeTime(v.first_seen)}
                    </TableCell>
                    <TableCell
                      className="text-xs text-muted-foreground"
                      title={v.last_seen ?? undefined}
                    >
                      {relativeTime(v.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
                {data && data.items.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center text-muted-foreground py-12"
                    >
                      {search || domainFilter !== ALL || typeFilter !== ALL
                        ? "No victims match these filters."
                        : noDomainsMonitored
                          ? "Add a monitored domain above to start tracking victims."
                          : "No victims tracked yet — observed emails on monitored domains will appear here as kits flow through."}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {data && (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onOffsetChange={setOffset}
        />
      )}
    </div>
  );
}

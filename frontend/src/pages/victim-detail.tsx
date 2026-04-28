import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Check,
  Pencil,
  X,
  Mail,
  CalendarClock,
  Activity,
  StickyNote,
} from "lucide-react";
import { toast } from "sonner";

import {
  useVictim,
  useUpdateVictim,
  useVictimObservations,
} from "@/hooks/use-victims";
import { PageLoading } from "@/components/shared/loading";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type {
  VictimObservationSource,
  VictimType,
} from "@/types/api";

const TYPE_LABEL: Record<VictimType, string> = {
  user: "User",
  exec: "Exec",
  distro: "Distro",
  shared_mailbox: "Shared mailbox",
  service: "Service",
  unknown: "Unknown",
};

const TYPE_BADGE_VARIANT: Record<
  VictimType,
  "default" | "secondary" | "outline" | "destructive"
> = {
  user: "secondary",
  exec: "destructive",
  distro: "outline",
  shared_mailbox: "outline",
  service: "outline",
  unknown: "outline",
};

const SOURCE_LABEL: Record<VictimObservationSource, string> = {
  oauth_state: "OAuth state",
  oauth_login_hint: "OAuth login_hint",
  aitm_url_fragment: "AITM URL fragment",
  eml_to: "EML To-header",
  eml_cc: "EML Cc-header",
  eml_bcc: "EML Bcc-header",
  kit_content: "Kit content",
  other: "Other",
};

function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------------
// Inline display-name editor.  Pencil-icon-on-hover affordance + save on
// Enter / blur, cancel on Escape.  Empty save = clear (back to email-only
// view in the trigger).
// ---------------------------------------------------------------------------

function EditableDisplayName({
  value,
  onSave,
  isPending,
}: {
  value: string | null;
  onSave: (next: string | null) => void;
  isPending?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");
  // Reset the draft when the upstream ``value`` changes — e.g. after
  // a successful save invalidates the query and refetches.  Per
  // https://react.dev/learn/you-might-not-need-an-effect, the right
  // pattern for "sync state with prop" is to track the previous prop
  // and reset during render rather than via useEffect.
  const [previousValue, setPreviousValue] = useState(value);
  if (previousValue !== value) {
    setPreviousValue(value);
    setDraft(value ?? "");
  }

  if (editing) {
    return (
      <div className="flex items-center gap-2">
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              const next = draft.trim();
              onSave(next || null);
              setEditing(false);
            } else if (e.key === "Escape") {
              setDraft(value ?? "");
              setEditing(false);
            }
          }}
          autoFocus
          placeholder="John Smith — VP Finance"
          className="max-w-md"
        />
        <Button
          size="sm"
          variant="ghost"
          className="h-8 px-2"
          onClick={() => {
            const next = draft.trim();
            onSave(next || null);
            setEditing(false);
          }}
          disabled={isPending}
        >
          <Check className="h-4 w-4" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="h-8 px-2"
          onClick={() => {
            setDraft(value ?? "");
            setEditing(false);
          }}
        >
          <X className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div
      className="group inline-flex items-center gap-2 cursor-pointer"
      onClick={() => setEditing(true)}
    >
      {value ? (
        <span className="text-base text-foreground">{value}</span>
      ) : (
        <span className="text-sm text-muted-foreground italic">
          Add a display name…
        </span>
      )}
      <Pencil className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Notes — same EditableDescription pattern but local to this page so we
// don't need to generalize the shared component yet.
// ---------------------------------------------------------------------------

function EditableNotes({
  value,
  onSave,
  isPending,
}: {
  value: string | null;
  onSave: (next: string | null) => void;
  isPending?: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");
  const [previousValue, setPreviousValue] = useState(value);
  if (previousValue !== value) {
    setPreviousValue(value);
    setDraft(value ?? "");
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <StickyNote className="h-4 w-4" />
            Operator notes
          </CardTitle>
          {!editing && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2"
              onClick={() => setEditing(true)}
            >
              <Pencil className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {editing ? (
          <div className="space-y-2">
            <textarea
              className="flex min-h-[100px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-y"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              autoFocus
              placeholder="Notes — context the pipeline can't infer (recent role change, leaving the org, special handling, etc.)"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                className="h-7"
                onClick={() => {
                  const next = draft.trim();
                  onSave(next || null);
                  setEditing(false);
                }}
                disabled={isPending}
              >
                <Check className="h-3.5 w-3.5 mr-1" />
                {isPending ? "Saving…" : "Save"}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7"
                onClick={() => {
                  setDraft(value ?? "");
                  setEditing(false);
                }}
              >
                <X className="h-3.5 w-3.5 mr-1" />
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <p
            className="text-sm text-muted-foreground cursor-pointer hover:text-foreground transition-colors whitespace-pre-wrap"
            onClick={() => setEditing(true)}
          >
            {value || "No notes — click to add"}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Source-channel breakdown — cheap client-side aggregation over the
// observations response so we don't need a dedicated backend stats
// endpoint for it.  Pagination caveat: when total > limit, this only
// reflects the current page.  100 is the default limit, which covers
// almost every real victim's full observation history.
// ---------------------------------------------------------------------------

function SourceBreakdown({
  observations,
}: {
  observations: { source: VictimObservationSource }[];
}) {
  const counts = useMemo(() => {
    const m: Partial<Record<VictimObservationSource, number>> = {};
    for (const o of observations) {
      m[o.source] = (m[o.source] ?? 0) + 1;
    }
    return Object.entries(m).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0));
  }, [observations]);

  if (counts.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No observations yet.</p>
    );
  }

  const max = Math.max(...counts.map(([, n]) => n ?? 0));

  return (
    <div className="space-y-2">
      {counts.map(([source, count]) => (
        <div
          key={source}
          className="flex items-center gap-3 text-sm"
        >
          <span className="w-44 shrink-0 text-muted-foreground">
            {SOURCE_LABEL[source as VictimObservationSource] ?? source}
          </span>
          <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-emerald-500/80 transition-all"
              style={{ width: `${((count ?? 0) / max) * 100}%` }}
            />
          </div>
          <span className="w-10 text-right font-mono">{count}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function VictimDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: victim, isLoading } = useVictim(id);
  const { data: obsData } = useVictimObservations(id, 0, 100);
  const update = useUpdateVictim();

  if (isLoading || !victim || !id) return <PageLoading />;

  const renderTypeName = (value: string | null) => {
    if (!value) return TYPE_LABEL[victim.type];
    return TYPE_LABEL[value as VictimType] ?? value;
  };

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/phishprint"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          PhishPrint
        </Link>
      </div>

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="space-y-2 min-w-0">
          <div className="flex items-center gap-2">
            <Mail className="h-5 w-5 text-muted-foreground shrink-0" />
            <h1 className="text-2xl font-bold tracking-tight font-mono break-all">
              {victim.email}
            </h1>
          </div>
          <EditableDisplayName
            value={victim.display_name}
            onSave={(next) =>
              update.mutate(
                { id, display_name: next },
                {
                  onSuccess: () => toast.success("Display name updated"),
                  onError: (err) => toast.error(err.message),
                },
              )
            }
            isPending={update.isPending}
          />
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">Type</span>
          <Select
            value={victim.type}
            onValueChange={(v) =>
              update.mutate(
                { id, type: v as VictimType },
                {
                  onSuccess: () => toast.success("Type updated"),
                  onError: (err) => toast.error(err.message),
                },
              )
            }
          >
            <SelectTrigger className="w-44">
              <SelectValue>{renderTypeName}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              {(Object.keys(TYPE_LABEL) as VictimType[]).map((t) => (
                <SelectItem key={t} value={t}>
                  {TYPE_LABEL[t]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card>
        <CardContent className="grid gap-4 p-4 md:grid-cols-4">
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Activity className="h-3 w-3" />
              Type
            </span>
            <div className="mt-1">
              <Badge variant={TYPE_BADGE_VARIANT[victim.type]}>
                {TYPE_LABEL[victim.type]}
              </Badge>
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Domain</span>
            <p className="font-mono text-sm mt-1">{victim.domain}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              First seen
            </span>
            <p className="text-sm mt-1">{formatTime(victim.first_seen)}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              Last seen
            </span>
            <p className="text-sm mt-1">{formatTime(victim.last_seen)}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">
              Total observations
            </span>
            <p className="text-sm mt-1 font-medium">
              {obsData?.total ?? "—"}
            </p>
          </div>
        </CardContent>
      </Card>

      <EditableNotes
        value={victim.notes}
        onSave={(next) =>
          update.mutate(
            { id, notes: next },
            {
              onSuccess: () => toast.success("Notes updated"),
              onError: (err) => toast.error(err.message),
            },
          )
        }
        isPending={update.isPending}
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">
            Source-channel breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SourceBreakdown observations={obsData?.items ?? []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Observations
            {obsData && (
              <span className="text-xs text-muted-foreground font-normal ml-2">
                ({obsData.total})
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Observed</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Kit</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>SHA256</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(obsData?.items ?? []).map((o) => (
                <TableRow key={o.id}>
                  <TableCell
                    className="text-xs whitespace-nowrap text-muted-foreground"
                    title={o.observed_at}
                  >
                    {formatTime(o.observed_at)}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {SOURCE_LABEL[o.source]}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    <Link
                      to={`/kits/${o.kit.id}`}
                      className="hover:underline"
                    >
                      {o.kit.source_url}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <KitStatusBadge status={o.kit.status as never} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {o.kit.sha256?.slice(0, 12) ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
              {obsData && obsData.items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-center text-muted-foreground py-8"
                  >
                    No observations recorded yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

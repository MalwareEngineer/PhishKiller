import { useState } from "react";
import { Link } from "react-router-dom";
import { useKits } from "@/hooks/use-kits";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Sparkles } from "lucide-react";

const PAGE_SIZE = 25;

/**
 * PhishMatch landing page — a triage queue of analyzed kits.
 *
 * Manual-first attribution means the analyst decides *which* kits to
 * score; this page just gives them a convenient list rather than forcing
 * a kit-detail-page pivot.  Clicking a row opens the per-kit scorer.
 */
export function PhishMatchInboxPage() {
  const [offset, setOffset] = useState(0);
  const { data, isLoading } = useKits({
    offset,
    limit: PAGE_SIZE,
    status_filter: "analyzed",
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Sparkles className="h-5 w-5 text-emerald-500" />
        <h1 className="text-2xl font-bold tracking-tight">PhishMatch</h1>
      </div>
      <p className="text-sm text-muted-foreground max-w-3xl">
        Similarity-scored attribution suggestions. Pick an analyzed kit to see
        its ranked candidate actors, families, and campaigns with per-signal
        evidence (TLSH, shared IOCs, YARA rules, redirect hosts, source URL).
        Nothing is linked automatically — every attribution is an explicit
        click, and the evidence snapshot is saved on the junction row for
        audit.
      </p>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <TableLoading />
          ) : items.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No analyzed kits yet — submit a kit and wait for analysis to
              finish.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Source URL</TableHead>
                  <TableHead>SHA256</TableHead>
                  <TableHead>Analyzed</TableHead>
                  <TableHead className="w-24 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((kit) => (
                  <TableRow key={kit.id}>
                    <TableCell>
                      <KitStatusBadge status={kit.status} />
                    </TableCell>
                    <TableCell className="max-w-md truncate font-mono text-xs">
                      <Link
                        to={`/kits/${kit.id}`}
                        className="hover:underline"
                        title={kit.source_url}
                      >
                        {kit.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {kit.sha256?.slice(0, 12) ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(kit.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link to={`/phish-match/${kit.id}`}>
                        <Button size="sm" variant="outline">
                          <Sparkles className="h-3.5 w-3.5 mr-1" />
                          Match
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {total > PAGE_SIZE && (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={total}
          onOffsetChange={setOffset}
        />
      )}
    </div>
  );
}

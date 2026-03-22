import { useState } from "react";
import { useFeedEntries, useFeedStats, useIngestFeeds } from "@/hooks/use-feeds";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RefreshCw } from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 50;

export function FeedsPage() {
  const [offset, setOffset] = useState(0);
  const [source, setSource] = useState<string>("all");

  const { data: stats } = useFeedStats();
  const { data, isLoading } = useFeedEntries({
    offset,
    limit: PAGE_SIZE,
    source: source === "all" ? undefined : source,
  });
  const ingest = useIngestFeeds();

  const handleIngest = () => {
    ingest.mutate(undefined, {
      onSuccess: () => toast.success("Feed ingestion triggered"),
      onError: (err) => toast.error(err.message),
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Feeds</h1>
        <Button size="sm" onClick={handleIngest} disabled={ingest.isPending}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Trigger Ingestion
        </Button>
      </div>

      {/* Stats cards */}
      <div className="grid gap-4 md:grid-cols-3">
        {(stats ?? []).map((s) => (
          <Card key={s.source}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium capitalize">{s.source}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Total</span>
                <span className="font-medium">{s.total.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Processed</span>
                <span className="text-emerald-500">{s.processed.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Pending</span>
                <span className="text-amber-500">{s.unprocessed.toLocaleString()}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <Select value={source} onValueChange={(v) => { if (v) { setSource(v); setOffset(0); } }}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Filter source" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            <SelectItem value="phishtank">PhishTank</SelectItem>
            <SelectItem value="openphish">OpenPhish</SelectItem>
            <SelectItem value="certstream">CertStream</SelectItem>
            <SelectItem value="manual">Manual</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><TableLoading /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Target Brand</TableHead>
                  <TableHead>Processed</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs capitalize">{entry.source}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-md truncate">{entry.url}</TableCell>
                    <TableCell className="text-sm">{entry.target_brand ?? "—"}</TableCell>
                    <TableCell>
                      <Badge variant={entry.is_processed ? "default" : "outline"} className="text-xs">
                        {entry.is_processed ? "Yes" : "No"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(entry.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">No feed entries</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {data && <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onOffsetChange={setOffset} />}
    </div>
  );
}

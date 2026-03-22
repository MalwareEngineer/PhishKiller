import { useState } from "react";
import { Link } from "react-router-dom";
import { useIndicators, useIndicatorSearch, useIndicatorStats } from "@/hooks/use-indicators";
import { IocTypeBadge } from "@/components/shared/ioc-type-badge";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import type { IndicatorType } from "@/types/api";

const IOC_TYPES: (IndicatorType | "all")[] = [
  "all", "email", "c2_url", "domain", "ip_address", "telegram_bot_token",
  "telegram_chat_id", "smtp_credential", "cryptocurrency_wallet", "phone_number",
  "base64_block", "source_url",
];

const PAGE_SIZE = 50;

export function IndicatorsPage() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const filterParams = {
    offset,
    limit: PAGE_SIZE,
    type_filter: typeFilter === "all" ? undefined : typeFilter as IndicatorType,
  };

  const listQuery = useIndicators(search ? undefined : filterParams);
  const searchQuery = useIndicatorSearch(search, filterParams);
  const { data: stats } = useIndicatorStats();

  const data = search ? searchQuery.data : listQuery.data;
  const isLoading = search ? searchQuery.isLoading : listQuery.isLoading;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">Indicators</h1>

      <div className="flex items-center gap-3">
        <Input
          placeholder="Search IOCs..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
          className="max-w-sm"
        />
        <Select value={typeFilter} onValueChange={(v) => { if (v) { setTypeFilter(v); setOffset(0); } }}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter type" />
          </SelectTrigger>
          <SelectContent>
            {IOC_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t === "all" ? "All types" : t.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-4 md:grid-cols-[1fr_250px]">
        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-4"><TableLoading /></div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Source File</TableHead>
                    <TableHead>Kit</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.items ?? []).map((ioc) => (
                    <TableRow key={ioc.id}>
                      <TableCell><IocTypeBadge type={ioc.type} /></TableCell>
                      <TableCell className="font-mono text-xs break-all max-w-xs">{ioc.value}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Progress value={ioc.confidence} className="h-1.5 w-12" />
                          <span className="text-xs">{ioc.confidence}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground truncate max-w-32">
                        {ioc.source_file ?? "—"}
                      </TableCell>
                      <TableCell>
                        <Link to={`/kits/${ioc.kit_id}`} className="text-xs font-mono hover:underline">
                          {ioc.kit_id.slice(0, 8)}
                        </Link>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(ioc.created_at).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                  {data?.items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                        No indicators found
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Stats sidebar */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">IOC Counts</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(stats ?? []).map((s) => (
              <div key={s.type} className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{s.type.replace(/_/g, " ")}</span>
                <span className="font-medium">{s.count.toLocaleString()}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {data && <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onOffsetChange={setOffset} />}
    </div>
  );
}

import { Link } from "react-router-dom";
import { useKits } from "@/hooks/use-kits";
import { useIndicatorStats } from "@/hooks/use-indicators";
import { useInvestigations } from "@/hooks/use-investigations";
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
import { Skeleton } from "@/components/ui/skeleton";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
} from "recharts";
import { Package, CheckCircle, XCircle, GitBranch } from "lucide-react";
const IOC_COLORS = [
  "#a855f7", "#3b82f6", "#ef4444", "#f97316", "#06b6d4",
  "#ec4899", "#64748b", "#14b8a6", "#eab308", "#6366f1", "#8b5cf6",
];

export function DashboardPage() {
  const { data: kitsData, isLoading: kitsLoading } = useKits({ limit: 10 });
  const { data: allKits } = useKits({ limit: 1 });
  const { data: analyzedKits } = useKits({ limit: 1, status_filter: "analyzed" });
  const { data: failedKits } = useKits({ limit: 1, status_filter: "failed" });
  const { data: investigationsData } = useInvestigations(0, 1);
  const { data: iocStats, isLoading: iocLoading } = useIndicatorStats();

  const statusCounts: { name: string; value: number; color: string }[] = [];
  if (allKits) {
    const total = allKits.total;
    const analyzed = analyzedKits?.total ?? 0;
    const failed = failedKits?.total ?? 0;
    const rest = total - analyzed - failed;
    if (rest > 0) statusCounts.push({ name: "In Progress", value: rest, color: "#f59e0b" });
    if (analyzed > 0) statusCounts.push({ name: "Analyzed", value: analyzed, color: "#10b981" });
    if (failed > 0) statusCounts.push({ name: "Failed", value: failed, color: "#ef4444" });
  }

  const iocChartData = (iocStats ?? []).map((s, i) => ({
    type: s.type.replace(/_/g, " "),
    count: s.count,
    fill: IOC_COLORS[i % IOC_COLORS.length],
  }));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatsCard
          title="Total Kits"
          value={allKits?.total}
          icon={<Package className="h-4 w-4 text-muted-foreground" />}
          loading={!allKits}
        />
        <StatsCard
          title="Analyzed"
          value={analyzedKits?.total}
          icon={<CheckCircle className="h-4 w-4 text-emerald-500" />}
          loading={!analyzedKits}
        />
        <StatsCard
          title="Failed"
          value={failedKits?.total}
          icon={<XCircle className="h-4 w-4 text-red-500" />}
          loading={!failedKits}
        />
        <StatsCard
          title="Investigations"
          value={investigationsData?.total}
          icon={<GitBranch className="h-4 w-4 text-blue-500" />}
          loading={!investigationsData}
        />
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Kit Status Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {statusCounts.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={statusCounts}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {statusCounts.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ background: "#1e1e2e", border: "1px solid #333", borderRadius: 8 }}
                    labelStyle={{ color: "#ccc" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Skeleton className="h-[200px]" />
            )}
            <div className="flex justify-center gap-4 text-xs text-muted-foreground">
              {statusCounts.map((s) => (
                <div key={s.name} className="flex items-center gap-1.5">
                  <div className="h-2.5 w-2.5 rounded-full" style={{ background: s.color }} />
                  {s.name}: {s.value}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">IOC Type Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {iocLoading ? (
              <Skeleton className="h-[200px]" />
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={iocChartData} layout="vertical">
                  <XAxis type="number" tick={{ fill: "#888", fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="type"
                    tick={{ fill: "#888", fontSize: 11 }}
                    width={100}
                  />
                  <RechartsTooltip
                    contentStyle={{ background: "#1e1e2e", border: "1px solid #333", borderRadius: 8 }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {iocChartData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Kits */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Recent Kits</CardTitle>
          <Link to="/kits" className="text-xs text-muted-foreground hover:text-foreground">
            View all →
          </Link>
        </CardHeader>
        <CardContent>
          {kitsLoading ? (
            <Skeleton className="h-[200px]" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Source URL</TableHead>
                  <TableHead>SHA256</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(kitsData?.items ?? []).map((kit) => (
                  <TableRow key={kit.id}>
                    <TableCell>
                      <KitStatusBadge status={kit.status} />
                    </TableCell>
                    <TableCell className="max-w-[300px] truncate font-mono text-xs">
                      <Link to={`/kits/${kit.id}`} className="hover:underline">
                        {kit.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {kit.sha256?.slice(0, 12)}...
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {kit.file_size ? `${(kit.file_size / 1024).toFixed(1)} KB` : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(kit.created_at).toLocaleString()}
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

function StatsCard({
  title,
  value,
  icon,
  loading,
}: {
  title: string;
  value?: number;
  icon: React.ReactNode;
  loading: boolean;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-7 w-16" />
        ) : (
          <div className="text-2xl font-bold">{value?.toLocaleString() ?? 0}</div>
        )}
      </CardContent>
    </Card>
  );
}

import { useParams, Link } from "react-router-dom";
import { useInvestigation, useInvestigationTree, useUpdateInvestigation } from "@/hooks/use-investigations";
import { EditableDescription } from "@/components/shared/editable-description";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import type { InvestigationTreeNode } from "@/types/api";

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: inv, isLoading } = useInvestigation(id!);
  const { data: tree } = useInvestigationTree(id!);
  const updateMutation = useUpdateInvestigation();

  if (isLoading || !inv) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight">
          {inv.name ?? `Investigation ${inv.id.slice(0, 8)}`}
        </h1>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Badge variant={inv.status === "completed" ? "default" : "secondary"}>
            {inv.status}
          </Badge>
          <span>{inv.total_kits} kits</span>
          <span>depth {inv.total_depth_reached}/{inv.max_depth}</span>
          <span>{new Date(inv.created_at).toLocaleString()}</span>
        </div>
      </div>

      <EditableDescription
        value={inv.description}
        onSave={(description) =>
          updateMutation.mutate(
            { id: id!, description },
            {
              onSuccess: () => toast.success("Description updated"),
              onError: (err) => toast.error(err.message),
            }
          )
        }
        isPending={updateMutation.isPending}
      />

      {inv.root_kit && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Root Kit</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <KitStatusBadge status={inv.root_kit.status} />
              <Link to={`/kits/${inv.root_kit.id}`} className="font-mono text-sm hover:underline">
                {inv.root_kit.source_url}
              </Link>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Investigation Tree</CardTitle>
        </CardHeader>
        <CardContent>
          {tree && tree.length > 0 ? (
            <div className="space-y-1">
              {tree.map((node) => (
                <TreeNodeView key={node.kit.id} node={node} depth={0} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No tree data available</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function TreeNodeView({ node, depth }: { node: InvestigationTreeNode; depth: number }) {
  return (
    <div>
      <div
        className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/50")}
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
      >
        {depth > 0 && <span className="text-muted-foreground">└─</span>}
        <KitStatusBadge status={node.kit.status} />
        <Link to={`/kits/${node.kit.id}`} className="font-mono text-xs hover:underline truncate max-w-md">
          {node.kit.source_url}
        </Link>
        {node.discovery_method && (
          <Badge variant="outline" className="text-[10px]">
            {node.discovery_method}
          </Badge>
        )}
      </div>
      {node.children.map((child) => (
        <TreeNodeView key={child.kit.id} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

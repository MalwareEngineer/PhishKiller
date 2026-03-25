import { useParams, Link, useNavigate } from "react-router-dom";
import { useCampaign, useDeleteCampaign } from "@/hooks/use-campaigns";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";

export function CampaignDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: campaign, isLoading } = useCampaign(id!);
  const deleteMutation = useDeleteCampaign();

  if (isLoading || !campaign) return <PageLoading />;

  const handleDelete = () => {
    if (!window.confirm(`Delete campaign "${campaign.name}"? Linked kits will be unlinked but not deleted.`)) return;
    deleteMutation.mutate(id!, {
      onSuccess: () => navigate("/campaigns"),
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">{campaign.name}</h1>
        <Button
          variant="destructive"
          size="sm"
          onClick={handleDelete}
          disabled={deleteMutation.isPending}
        >
          <Trash2 className="h-4 w-4 mr-1" />
          {deleteMutation.isPending ? "Deleting…" : "Delete"}
        </Button>
      </div>
      <div>
        {campaign.target_brand && (
          <p className="text-sm text-muted-foreground mt-1">Target: {campaign.target_brand}</p>
        )}
        {campaign.description && (
          <p className="text-sm mt-2">{campaign.description}</p>
        )}
      </div>

      {campaign.actors.length > 0 && (
        <div>
          <h2 className="text-sm font-medium mb-2">Linked Actors</h2>
          <div className="flex flex-wrap gap-2">
            {campaign.actors.map((a) => (
              <Link key={a.id} to={`/actors/${a.id}`}>
                <Badge variant="outline" className="cursor-pointer hover:bg-muted">{a.name}</Badge>
              </Link>
            ))}
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Kits ({campaign.kits.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Source URL</TableHead>
                <TableHead>SHA256</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {campaign.kits.map((kit) => (
                <TableRow key={kit.id}>
                  <TableCell><KitStatusBadge status={kit.status} /></TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    <Link to={`/kits/${kit.id}`} className="hover:underline">{kit.source_url}</Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {kit.sha256?.slice(0, 12) ?? "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(kit.created_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
              {campaign.kits.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground py-8">No kits linked</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

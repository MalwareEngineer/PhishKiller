import { Link, useNavigate, useParams } from "react-router-dom";
import { useFamily, useDeleteFamily, useUpdateFamily } from "@/hooks/use-families";
import { EditableDescription } from "@/components/shared/editable-description";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";
import { SuggestedKitsPanel } from "@/components/shared/suggested-kits-panel";

export function FamilyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: family, isLoading } = useFamily(id!);
  const deleteMutation = useDeleteFamily();
  const updateMutation = useUpdateFamily();

  if (isLoading || !family) return <PageLoading />;

  const handleDelete = () => {
    if (!window.confirm(`Delete family "${family.name}"? Linked kits will be unlinked but not deleted.`)) return;
    deleteMutation.mutate(id!, {
      onSuccess: () => navigate("/families"),
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">{family.name}</h1>
        <Button
          variant="destructive"
          size="sm"
          onClick={handleDelete}
          disabled={deleteMutation.isPending}
        >
          <Trash2 className="h-4 w-4 mr-1" />
          {deleteMutation.isPending ? "Deleting..." : "Delete"}
        </Button>
      </div>

      <EditableDescription
        value={family.description}
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

      <Card>
        <CardContent className="grid gap-4 p-4 md:grid-cols-2">
          <div>
            <span className="text-xs text-muted-foreground">Aliases</span>
            <div className="flex flex-wrap gap-1 mt-1">
              {(family.aliases ?? []).map((a) => (
                <Badge key={a} variant="outline">{a}</Badge>
              ))}
              {(!family.aliases || family.aliases.length === 0) && <span className="text-sm">-</span>}
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Linked Actors</span>
            <div className="flex flex-wrap gap-1 mt-1">
              {(family.actors ?? []).map((actor) => (
                <Link key={actor.id} to={`/actors/${actor.id}`}>
                  <Badge variant="secondary" className="cursor-pointer hover:bg-secondary/80">
                    {actor.name}
                  </Badge>
                </Link>
              ))}
              {(!family.actors || family.actors.length === 0) && <span className="text-sm">-</span>}
            </div>
          </div>
        </CardContent>
      </Card>

      <SuggestedKitsPanel
        entityType="family"
        entityId={id!}
        entityName={family.name}
      />
    </div>
  );
}

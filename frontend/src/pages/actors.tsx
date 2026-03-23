import { useState } from "react";
import { Link } from "react-router-dom";
import { useActors, useCreateActor } from "@/hooks/use-actors";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus } from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 25;

export function ActorsPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");

  const { data, isLoading } = useActors(offset, PAGE_SIZE);
  const create = useCreateActor();

  const handleCreate = () => {
    if (!name.trim()) return;
    create.mutate(
      { name: name.trim() },
      {
        onSuccess: () => {
          toast.success("Actor created");
          setName("");
          setOpen(false);
        },
        onError: (err) => toast.error(err.message),
      }
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Actors</h1>
        <Button size="sm" onClick={() => setOpen(true)}><Plus className="mr-2 h-4 w-4" />New Actor</Button>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogContent>
            <DialogHeader><DialogTitle>Create Actor</DialogTitle></DialogHeader>
            <Input placeholder="Actor name" value={name} onChange={(e) => setName(e.target.value)} />
            <DialogFooter>
              <Button onClick={handleCreate} disabled={create.isPending}>Create</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><TableLoading /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Aliases</TableHead>
                  <TableHead>First Seen</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((actor) => (
                  <TableRow key={actor.id}>
                    <TableCell>
                      <Link to={`/actors/${actor.id}`} className="font-medium hover:underline">
                        {actor.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(actor.aliases ?? []).map((a) => (
                          <Badge key={a} variant="outline" className="text-xs">{a}</Badge>
                        ))}
                        {(!actor.aliases || actor.aliases.length === 0) && (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{actor.first_seen ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{actor.last_seen ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(actor.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">No actors found</TableCell>
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

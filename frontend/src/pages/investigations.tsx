import { useState } from "react";
import { Link } from "react-router-dom";
import { useInvestigations, useCreateInvestigation } from "@/hooks/use-investigations";
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

export function InvestigationsPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("");

  const { data, isLoading } = useInvestigations(offset, PAGE_SIZE);
  const create = useCreateInvestigation();

  const handleCreate = () => {
    if (!url.trim()) return;
    create.mutate(
      { url: url.trim() },
      {
        onSuccess: () => {
          toast.success("Investigation started");
          setUrl("");
          setOpen(false);
        },
        onError: (err) => toast.error(err.message),
      }
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Investigations</h1>
        <Button size="sm" onClick={() => setOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Investigation
        </Button>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Start Investigation</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <Input placeholder="https://..." value={url} onChange={(e) => setUrl(e.target.value)} />
            </div>
            <DialogFooter>
              <Button onClick={handleCreate} disabled={create.isPending}>
                {create.isPending ? "Starting..." : "Start"}
              </Button>
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
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Total Kits</TableHead>
                  <TableHead>Depth</TableHead>
                  <TableHead>Max Depth</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((inv) => (
                  <TableRow key={inv.id}>
                    <TableCell>
                      <Badge variant={inv.status === "completed" ? "default" : "secondary"}>
                        {inv.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Link to={`/investigations/${inv.id}`} className="hover:underline">
                        {inv.name ?? inv.id.slice(0, 8)}
                      </Link>
                    </TableCell>
                    <TableCell>{inv.total_kits}</TableCell>
                    <TableCell>{inv.total_depth_reached}</TableCell>
                    <TableCell>{inv.max_depth}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(inv.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                      No investigations yet
                    </TableCell>
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

import { useState } from "react";
import { Link } from "react-router-dom";
import { useCampaigns, useCreateCampaign } from "@/hooks/use-campaigns";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus } from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 25;

export function CampaignsPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [targetBrand, setTargetBrand] = useState("");

  const { data, isLoading } = useCampaigns({ offset, limit: PAGE_SIZE });
  const create = useCreateCampaign();

  const handleCreate = () => {
    if (!name.trim()) return;
    create.mutate(
      { name: name.trim(), target_brand: targetBrand.trim() || undefined },
      {
        onSuccess: () => {
          toast.success("Campaign created");
          setName(""); setTargetBrand(""); setOpen(false);
        },
        onError: (err) => toast.error(err.message),
      }
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Campaigns</h1>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger >
            <Button size="sm"><Plus className="mr-2 h-4 w-4" />New Campaign</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Create Campaign</DialogTitle></DialogHeader>
            <div className="space-y-3">
              <Input placeholder="Campaign name" value={name} onChange={(e) => setName(e.target.value)} />
              <Input placeholder="Target brand (optional)" value={targetBrand} onChange={(e) => setTargetBrand(e.target.value)} />
            </div>
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
                  <TableHead>Target Brand</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>End</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((c) => (
                  <TableRow key={c.id}>
                    <TableCell>
                      <Link to={`/campaigns/${c.id}`} className="font-medium hover:underline">{c.name}</Link>
                    </TableCell>
                    <TableCell className="text-sm">{c.target_brand ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{c.start_date ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{c.end_date ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(c.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">No campaigns found</TableCell>
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

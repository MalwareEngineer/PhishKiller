import { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { useInvestigations, useCreateInvestigation, useBulkDeleteInvestigations } from "@/hooks/use-investigations";
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
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 25;

export function InvestigationsPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("");

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Clear selection on page change
  useEffect(() => {
    setSelectedIds(new Set());
  }, [offset]);

  const { data, isLoading } = useInvestigations(offset, PAGE_SIZE);
  const create = useCreateInvestigation();
  const bulkDeleteMutation = useBulkDeleteInvestigations();

  const items = data?.items ?? [];
  const pageIds = useMemo(() => items.map((inv) => inv.id), [items]);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
  const somePageSelected = pageIds.some((id) => selectedIds.has(id));

  const toggleSelectAll = () => {
    if (allPageSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of pageIds) next.delete(id);
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of pageIds) next.add(id);
        return next;
      });
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleBulkDelete = () => {
    const ids = Array.from(selectedIds);
    bulkDeleteMutation.mutate(ids, {
      onSuccess: (res) => {
        toast.success(`Deleted ${res.deleted} investigation${res.deleted !== 1 ? "s" : ""}`);
        setSelectedIds(new Set());
        setDeleteOpen(false);
      },
      onError: (err) => toast.error(err.message),
    });
  };

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

      {/* Selection action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-4 py-2">
          <span className="text-sm font-medium">
            {selectedIds.size} investigation{selectedIds.size !== 1 ? "s" : ""} selected
          </span>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-1.5 h-3.5 w-3.5" />
            Delete
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedIds(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      {/* Bulk delete confirmation */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {selectedIds.size} investigation{selectedIds.size !== 1 ? "s" : ""}?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently delete the selected investigations. Root kits and their
            descendants will be cascade-deleted. Other linked kits will be preserved but
            unlinked. This action cannot be undone.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleBulkDelete}
              disabled={bulkDeleteMutation.isPending}
            >
              {bulkDeleteMutation.isPending ? "Deleting..." : `Delete ${selectedIds.size} investigation${selectedIds.size !== 1 ? "s" : ""}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><TableLoading /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[40px] px-2">
                    <input
                      type="checkbox"
                      checked={allPageSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = somePageSelected && !allPageSelected;
                      }}
                      onChange={toggleSelectAll}
                      className="h-4 w-4 rounded border-input accent-primary cursor-pointer"
                    />
                  </TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Total Kits</TableHead>
                  <TableHead>Depth</TableHead>
                  <TableHead>Max Depth</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((inv) => (
                  <TableRow
                    key={inv.id}
                    className={`${selectedIds.has(inv.id) ? "bg-primary/5" : ""}`}
                  >
                    <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(inv.id)}
                        onChange={() => toggleSelect(inv.id)}
                        className="h-4 w-4 rounded border-input accent-primary cursor-pointer"
                      />
                    </TableCell>
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
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
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

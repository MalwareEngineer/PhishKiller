import { useState } from "react";
import { Link } from "react-router-dom";
import { useKits, useSubmitKit, useUploadKit } from "@/hooks/use-kits";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Upload } from "lucide-react";
import { toast } from "sonner";
import type { KitStatus } from "@/types/api";

const STATUSES: (KitStatus | "all")[] = ["all", "pending", "downloading", "analyzing", "analyzed", "failed"];
const PAGE_SIZE = 25;

export function KitsPage() {
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [submitUrl, setSubmitUrl] = useState("");
  const [submitOpen, setSubmitOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);

  const { data, isLoading } = useKits({
    offset,
    limit: PAGE_SIZE,
    status_filter: statusFilter === "all" ? undefined : statusFilter as KitStatus,
  });

  const submitMutation = useSubmitKit();
  const uploadMutation = useUploadKit();

  const handleSubmit = () => {
    if (!submitUrl.trim()) return;
    submitMutation.mutate(
      { url: submitUrl.trim() },
      {
        onSuccess: (res) => {
          toast.success(res.duplicate ? "Duplicate kit — already queued" : "Kit submitted for analysis");
          setSubmitUrl("");
          setSubmitOpen(false);
        },
        onError: (err) => toast.error(err.message),
      }
    );
  };

  const handleUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    uploadMutation.mutate(
      { file },
      {
        onSuccess: () => {
          toast.success("File uploaded for analysis");
          setUploadOpen(false);
        },
        onError: (err) => toast.error(err.message),
      }
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Kits</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setUploadOpen(true)}>
            <Upload className="mr-2 h-4 w-4" />
            Upload
          </Button>
          <Dialog open={uploadOpen} onOpenChange={setUploadOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Upload Phishing Kit</DialogTitle>
              </DialogHeader>
              <Input type="file" accept=".zip,.rar,.tar,.gz,.html,.eml" onChange={handleUpload} />
            </DialogContent>
          </Dialog>

          <Button size="sm" onClick={() => setSubmitOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Submit URL
          </Button>
          <Dialog open={submitOpen} onOpenChange={setSubmitOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Submit URL for Analysis</DialogTitle>
              </DialogHeader>
              <Input
                placeholder="https://example.com/phishing-kit.zip"
                value={submitUrl}
                onChange={(e) => setSubmitUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              />
              <DialogFooter>
                <Button onClick={handleSubmit} disabled={submitMutation.isPending}>
                  {submitMutation.isPending ? "Submitting..." : "Submit"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Select value={statusFilter} onValueChange={(v) => { if (v) { setStatusFilter(v); setOffset(0); } }}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Filter status" />
          </SelectTrigger>
          <SelectContent>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s === "all" ? "All statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4">
              <TableLoading rows={PAGE_SIZE} />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead>Source URL</TableHead>
                  <TableHead>SHA256</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Feed</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((kit) => (
                  <TableRow key={kit.id} className="cursor-pointer hover:bg-muted/50">
                    <TableCell>
                      <KitStatusBadge status={kit.status} />
                    </TableCell>
                    <TableCell className="max-w-[350px] truncate font-mono text-xs">
                      <Link to={`/kits/${kit.id}`} className="hover:underline">
                        {kit.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {kit.sha256 ? `${kit.sha256.slice(0, 12)}...` : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {kit.file_size ? `${(kit.file_size / 1024).toFixed(1)} KB` : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {kit.source_feed ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(kit.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                      No kits found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {data && (
        <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onOffsetChange={setOffset} />
      )}
    </div>
  );
}

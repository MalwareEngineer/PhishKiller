import { useState } from "react";
import { Link } from "react-router-dom";
import { useKits, useSubmitKit, useUploadKit, useBulkSubmitKits, useBulkUploadKits } from "@/hooks/use-kits";
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
import { Plus, Upload, X, FileText } from "lucide-react";
import { toast } from "sonner";
import type { KitStatus } from "@/types/api";

const STATUSES: (KitStatus | "all")[] = ["all", "pending", "downloading", "analyzing", "analyzed", "failed"];
const PAGE_SIZE = 25;

export function KitsPage() {
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Submit URL state
  const [submitOpen, setSubmitOpen] = useState(false);
  const [submitUrls, setSubmitUrls] = useState("");

  // Upload state
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);

  const { data, isLoading } = useKits({
    offset,
    limit: PAGE_SIZE,
    status_filter: statusFilter === "all" ? undefined : statusFilter as KitStatus,
  });

  const submitMutation = useSubmitKit();
  const bulkSubmitMutation = useBulkSubmitKits();
  const uploadMutation = useUploadKit();
  const bulkUploadMutation = useBulkUploadKits();

  const handleSubmit = () => {
    const urls = submitUrls
      .split("\n")
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    if (urls.length === 0) return;

    if (urls.length === 1) {
      submitMutation.mutate(
        { url: urls[0] },
        {
          onSuccess: (res) => {
            toast.success(res.duplicate ? "Duplicate kit — already queued" : "Kit submitted for analysis");
            setSubmitUrls("");
            setSubmitOpen(false);
          },
          onError: (err) => toast.error(err.message),
        }
      );
    } else {
      bulkSubmitMutation.mutate(urls, {
        onSuccess: (res) => {
          const msg = res.skipped_duplicate > 0
            ? `${res.submitted} URLs submitted (${res.skipped_duplicate} duplicates skipped)`
            : `${res.submitted} URLs submitted for analysis`;
          toast.success(msg);
          setSubmitUrls("");
          setSubmitOpen(false);
        },
        onError: (err) => toast.error(err.message),
      });
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    if (files.length > 0) {
      setSelectedFiles((prev) => [...prev, ...files]);
    }
    // Reset input so re-selecting the same file works
    e.target.value = "";
  };

  const removeFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleUpload = () => {
    if (selectedFiles.length === 0) return;

    if (selectedFiles.length === 1) {
      uploadMutation.mutate(
        { file: selectedFiles[0] },
        {
          onSuccess: () => {
            toast.success("File uploaded for analysis");
            setSelectedFiles([]);
            setUploadOpen(false);
          },
          onError: (err) => toast.error(err.message),
        }
      );
    } else {
      bulkUploadMutation.mutate(selectedFiles, {
        onSuccess: (res) => {
          toast.success(`${res.submitted} files uploaded for analysis`);
          setSelectedFiles([]);
          setUploadOpen(false);
        },
        onError: (err) => toast.error(err.message),
      });
    }
  };

  const isSubmitting = submitMutation.isPending || bulkSubmitMutation.isPending;
  const isUploading = uploadMutation.isPending || bulkUploadMutation.isPending;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Kits</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setUploadOpen(true)}>
            <Upload className="mr-2 h-4 w-4" />
            Upload
          </Button>
          <Dialog open={uploadOpen} onOpenChange={(open) => { setUploadOpen(open); if (!open) setSelectedFiles([]); }}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Upload Phishing Kits</DialogTitle>
              </DialogHeader>
              <div className="space-y-3">
                <Input
                  type="file"
                  accept=".zip,.rar,.tar,.gz,.html,.eml"
                  multiple
                  onChange={handleFileSelect}
                />
                {selectedFiles.length > 0 && (
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {selectedFiles.map((file, i) => (
                      <div key={`${file.name}-${i}`} className="flex items-center gap-2 text-sm text-muted-foreground bg-muted/50 rounded px-2 py-1">
                        <FileText className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate flex-1 font-mono text-xs">{file.name}</span>
                        <span className="text-xs shrink-0">{(file.size / 1024).toFixed(1)} KB</span>
                        <button onClick={() => removeFile(i)} className="shrink-0 hover:text-foreground">
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {selectedFiles.length === 0
                    ? "Select one or more files (.zip, .rar, .tar, .gz, .html, .eml)"
                    : `${selectedFiles.length} file${selectedFiles.length !== 1 ? "s" : ""} selected`}
                </p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setUploadOpen(false); setSelectedFiles([]); }}>
                  Cancel
                </Button>
                <Button onClick={handleUpload} disabled={selectedFiles.length === 0 || isUploading}>
                  {isUploading ? "Uploading..." : `Upload ${selectedFiles.length > 0 ? selectedFiles.length : ""} file${selectedFiles.length !== 1 ? "s" : ""}`}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Button size="sm" onClick={() => setSubmitOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Submit URLs
          </Button>
          <Dialog open={submitOpen} onOpenChange={(open) => { setSubmitOpen(open); if (!open) setSubmitUrls(""); }}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Submit URLs for Analysis</DialogTitle>
              </DialogHeader>
              <div className="space-y-2">
                <textarea
                  className="flex min-h-24 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 font-mono"
                  placeholder={"https://example.com/kit1.zip\nhttps://example.com/kit2.zip\nhttps://example.com/kit3.zip"}
                  value={submitUrls}
                  onChange={(e) => setSubmitUrls(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleSubmit();
                  }}
                />
                <p className="text-xs text-muted-foreground">
                  One URL per line. {submitUrls.split("\n").filter((u) => u.trim()).length > 0
                    ? `${submitUrls.split("\n").filter((u) => u.trim()).length} URL${submitUrls.split("\n").filter((u) => u.trim()).length !== 1 ? "s" : ""}`
                    : "Ctrl+Enter to submit"}
                </p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setSubmitOpen(false); setSubmitUrls(""); }}>
                  Cancel
                </Button>
                <Button onClick={handleSubmit} disabled={isSubmitting || !submitUrls.trim()}>
                  {isSubmitting ? "Submitting..." : "Submit"}
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
                  <TableHead>Source</TableHead>
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

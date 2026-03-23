import { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useKit, useKitSimilar, useReanalyzeKit, useDeleteKit, useKitDeletePreview } from "@/hooks/use-kits";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { IocTypeBadge } from "@/components/shared/ioc-type-badge";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { RefreshCw, Trash2, ArrowLeft, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

export function KitDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: kit, isLoading } = useKit(id!);
  const { data: similar } = useKitSimilar(id!, 100);
  const reanalyze = useReanalyzeKit();
  const deleteMut = useDeleteKit();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const { data: preview, isLoading: previewLoading } = useKitDeletePreview(id!, deleteOpen);

  if (isLoading || !kit) return <PageLoading />;

  const handleReanalyze = () => {
    reanalyze.mutate(id!, {
      onSuccess: () => toast.success("Re-analysis started"),
      onError: (err) => toast.error(err.message),
    });
  };

  const handleDelete = () => {
    deleteMut.mutate(id!, {
      onSuccess: () => {
        toast.success("Kit deleted");
        setDeleteOpen(false);
        navigate("/kits");
      },
      onError: (err) => toast.error(err.message),
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => navigate(-1)}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <KitStatusBadge status={kit.status} />
            {kit.discovery_method && (
              <Badge variant="secondary" className="text-xs">
                {kit.discovery_method}
              </Badge>
            )}
          </div>
          <p className="font-mono text-sm text-muted-foreground break-all max-w-2xl">
            {kit.source_url}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleReanalyze} disabled={reanalyze.isPending}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Reanalyze
          </Button>
          <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      {/* Hash info */}
      <Card>
        <CardContent className="grid gap-4 p-4 md:grid-cols-2 lg:grid-cols-4">
          <HashField label="SHA256" value={kit.sha256} />
          <HashField label="MD5" value={kit.md5} />
          <HashField label="SHA1" value={kit.sha1} />
          <HashField label="TLSH" value={kit.tlsh} />
          <div>
            <span className="text-xs text-muted-foreground">Filename</span>
            <p className="font-mono text-sm">{kit.filename ?? "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">MIME Type</span>
            <p className="text-sm">{kit.mime_type ?? "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Size</span>
            <p className="text-sm">{kit.file_size ? `${(kit.file_size / 1024).toFixed(1)} KB` : "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Chain Depth</span>
            <p className="text-sm">{kit.chain_depth}</p>
          </div>
        </CardContent>
      </Card>

      {kit.error_message && (
        <Card className="border-red-500/30">
          <CardContent className="p-4">
            <p className="text-sm text-red-400 font-mono">{kit.error_message}</p>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs defaultValue="indicators">
        <TabsList>
          <TabsTrigger value="indicators">
            Indicators ({kit.indicators.length})
          </TabsTrigger>
          <TabsTrigger value="analysis">
            Analysis ({kit.analysis_results.length})
          </TabsTrigger>
          <TabsTrigger value="similar">
            Similar ({similar?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="children">
            Children ({kit.child_kits.length})
          </TabsTrigger>
          <TabsTrigger value="campaigns">
            Campaigns ({kit.campaigns.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="indicators" className="mt-4">
          {kit.indicators.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No indicators extracted</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {kit.indicators.map((ioc) => (
                  <TableRow key={ioc.id}>
                    <TableCell>
                      <IocTypeBadge type={ioc.type} />
                    </TableCell>
                    <TableCell className="font-mono text-xs break-all max-w-lg">
                      {ioc.value}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Progress value={ioc.confidence} className="h-1.5 w-16" />
                        <span className="text-xs text-muted-foreground">{ioc.confidence}%</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="analysis" className="mt-4">
          {kit.analysis_results.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No analysis results yet</p>
          ) : (
            <Accordion multiple className="space-y-2">
              {kit.analysis_results.map((result) => (
                <AccordionItem key={result.id} value={result.id} className="border rounded-md px-4">
                  <AccordionTrigger className="text-sm">
                    <div className="flex items-center gap-3">
                      <Badge variant="secondary">{result.analysis_type}</Badge>
                      {result.duration_seconds != null && (
                        <span className="text-xs text-muted-foreground">
                          {result.duration_seconds.toFixed(2)}s
                        </span>
                      )}
                      {result.files_processed != null && (
                        <span className="text-xs text-muted-foreground">
                          {result.files_processed} files
                        </span>
                      )}
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <pre className="text-xs font-mono bg-muted/50 p-3 rounded-md overflow-auto max-h-64">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          )}
        </TabsContent>

        <TabsContent value="similar" className="mt-4">
          {!similar || similar.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No similar kits found</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source URL</TableHead>
                  <TableHead>TLSH</TableHead>
                  <TableHead>Distance</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {similar.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-mono text-xs max-w-md truncate">
                      <Link to={`/kits/${s.id}`} className="hover:underline">
                        {s.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {s.tlsh?.slice(0, 16)}...
                    </TableCell>
                    <TableCell className="text-sm">{s.distance}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="children" className="mt-4">
          {kit.child_kits.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No child kits</p>
          ) : (
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
                {kit.child_kits.map((child) => (
                  <TableRow key={child.id}>
                    <TableCell>
                      <KitStatusBadge status={child.status} />
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-md truncate">
                      <Link to={`/kits/${child.id}`} className="hover:underline">
                        {child.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {child.sha256?.slice(0, 12) ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(child.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </TabsContent>

        <TabsContent value="campaigns" className="mt-4">
          {kit.campaigns.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">Not linked to any campaigns</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {kit.campaigns.map((c) => (
                <Link key={c.id} to={`/campaigns/${c.id}`}>
                  <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                    {c.name}
                    {c.target_brand && ` (${c.target_brand})`}
                  </Badge>
                </Link>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Parent link */}
      {kit.parent_kit_id && (
        <div className="text-sm text-muted-foreground">
          Parent kit:{" "}
          <Link to={`/kits/${kit.parent_kit_id}`} className="font-mono hover:underline">
            {kit.parent_kit_id.slice(0, 8)}...
          </Link>
        </div>
      )}

      {kit.investigation_id && (
        <div className="text-sm text-muted-foreground">
          Investigation:{" "}
          <Link to={`/investigations/${kit.investigation_id}`} className="font-mono hover:underline">
            {kit.investigation_id.slice(0, 8)}...
          </Link>
        </div>
      )}

      {/* Delete confirmation dialog */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Confirm Deletion
            </DialogTitle>
          </DialogHeader>
          {previewLoading ? (
            <p className="text-sm text-muted-foreground py-4">Loading impact summary...</p>
          ) : preview ? (
            <div className="space-y-3">
              <p className="text-sm">This will permanently delete:</p>
              <ul className="text-sm space-y-1 ml-4 list-disc text-muted-foreground">
                <li>
                  <span className="text-foreground font-medium">{preview.total_kits}</span> kit{preview.total_kits !== 1 ? "s" : ""}
                  {preview.child_kits > 0 && (
                    <span> (including {preview.child_kits} child kit{preview.child_kits !== 1 ? "s" : ""})</span>
                  )}
                </li>
                {preview.indicators > 0 && (
                  <li><span className="text-foreground font-medium">{preview.indicators}</span> indicator{preview.indicators !== 1 ? "s" : ""}</li>
                )}
                {preview.analysis_results > 0 && (
                  <li><span className="text-foreground font-medium">{preview.analysis_results}</span> analysis result{preview.analysis_results !== 1 ? "s" : ""}</li>
                )}
                {preview.campaign_links > 0 && (
                  <li><span className="text-foreground font-medium">{preview.campaign_links}</span> campaign link{preview.campaign_links !== 1 ? "s" : ""}</li>
                )}
                {preview.investigations > 0 && (
                  <li><span className="text-foreground font-medium">{preview.investigations}</span> investigation{preview.investigations !== 1 ? "s" : ""}</li>
                )}
              </ul>
              <p className="text-xs text-muted-foreground">This action cannot be undone.</p>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMut.isPending || previewLoading}
            >
              {deleteMut.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function HashField({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <span className="text-xs text-muted-foreground">{label}</span>
      <p className="font-mono text-xs break-all">{value ?? "—"}</p>
    </div>
  );
}

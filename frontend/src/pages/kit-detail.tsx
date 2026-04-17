import { useState, useMemo } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useKit, useKitSimilar, useKitActors, useReanalyzeKit, useDeleteKit, useKitDeletePreview, useKitContent, useAddKitToCampaign, useAddKitToActor, useAddKitToFamily, useKitScreenshots, useKitNetworkLog, useKitBrowserResources, useForceRedownload } from "@/hooks/use-kits";
import { useCampaigns } from "@/hooks/use-campaigns";
import { useActors } from "@/hooks/use-actors";
import { useFamilies } from "@/hooks/use-families";
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
import { RefreshCw, Trash2, ArrowLeft, AlertTriangle, Search, ExternalLink, Plus, Download, FileDiff } from "lucide-react";
import { toast } from "sonner";
import type { AnalysisResultBrief } from "@/types/api";
import { TabScreenshots } from "@/components/kit-detail/tab-screenshots";
import { TabNetwork } from "@/components/kit-detail/tab-network";
import { TabResources } from "@/components/kit-detail/tab-resources";
import { AnalysisResultView } from "@/components/kit-detail/analysis-result-view";
import { AnalysisPipeline } from "@/components/kit-detail/analysis-pipeline";

// ── Helpers ──

interface YaraMatch {
  rule: string;
  namespace?: string;
  tags?: string[];
  meta?: Record<string, string>;
}

function getYaraMatches(results: AnalysisResultBrief[]): YaraMatch[] {
  const yaraResult = results.find((r) => r.analysis_type === "yara_scan");
  if (!yaraResult?.result_data) return [];
  const matches = yaraResult.result_data.matches;
  return Array.isArray(matches) ? matches : [];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const PREVIEW_LINES = 200;

function prettifyContent(raw: string): string {
  // Split minified HTML at tag boundaries for readability
  const hasLongLine = raw.length > 2000 && raw.indexOf("\n") === -1 || raw.split("\n").some(l => l.length > 500);
  if (!hasLongLine) return raw;
  return raw.replace(/></g, ">\n<");
}

interface ContentFile {
  filename: string;
  content: string;
  size: number;
  mime_type?: string;
  truncated?: boolean;
}

function ContentViewer({ file }: { file: ContentFile | undefined }) {
  const [expanded, setExpanded] = useState(false);

  const { lines, totalLines } = useMemo(() => {
    if (!file) return { lines: [], totalLines: 0 };
    const pretty = prettifyContent(file.content);
    const all = pretty.split("\n");
    return { lines: all, totalLines: all.length };
  }, [file]);

  if (!file) return null;

  const needsTruncation = totalLines > PREVIEW_LINES;
  const display = needsTruncation && !expanded ? lines.slice(0, PREVIEW_LINES) : lines;

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b bg-muted/30">
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="font-mono font-medium text-foreground">{file.filename}</span>
          <span>{formatBytes(file.size)}</span>
          {file.mime_type && <span className="opacity-60">{file.mime_type}</span>}
          <span className="opacity-60">{totalLines.toLocaleString()} lines</span>
        </div>
        <div className="flex items-center gap-2">
          {file.truncated && (
            <Badge variant="outline" className="text-xs text-yellow-400 border-yellow-400/30">
              truncated at 1MB
            </Badge>
          )}
        </div>
      </div>
      <pre className="text-xs font-mono leading-5 whitespace-pre p-4 overflow-auto max-h-[700px] m-0">
        {display.join("\n")}
      </pre>
      {needsTruncation && (
        <div className="border-t px-4 py-2 bg-muted/20">
          <Button
            variant="ghost"
            size="sm"
            className="text-xs"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded
              ? "Show less"
              : `Show all ${totalLines.toLocaleString()} lines (${formatBytes(file.size)})`}
          </Button>
        </div>
      )}
    </Card>
  );
}

// ── Main Page ──

export function KitDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: kit, isLoading } = useKit(id!);
  const { data: similar } = useKitSimilar(id!, 100);
  const reanalyze = useReanalyzeKit();
  const deleteMut = useDeleteKit();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const { data: preview, isLoading: previewLoading } = useKitDeletePreview(id!, deleteOpen);
  const [activeTab, setActiveTab] = useState("indicators");
  const { data: contentData, isLoading: contentLoading } = useKitContent(id!, activeTab === "content");
  const [selectedFile, setSelectedFile] = useState(0);
  const addToCampaign = useAddKitToCampaign();
  const addToActor = useAddKitToActor();
  const addToFamily = useAddKitToFamily();
  const { data: campaignsData } = useCampaigns({ limit: 200 });
  const { data: actorsData } = useActors(0, 200);
  const { data: familiesData } = useFamilies(0, 200);
  const { data: kitActors } = useKitActors(id!);
  const [selectedCampaignId, setSelectedCampaignId] = useState("");
  const [selectedActorId, setSelectedActorId] = useState("");
  const [selectedFamilyId, setSelectedFamilyId] = useState("");
  const { data: screenshotsData } = useKitScreenshots(id!, activeTab === "screenshots");
  const { data: networkData } = useKitNetworkLog(id!, activeTab === "network");
  const { data: resourcesData } = useKitBrowserResources(id!, activeTab === "resources");
  const forceRedownload = useForceRedownload();
  const [redownloadOpen, setRedownloadOpen] = useState(false);

  if (isLoading || !kit) return <PageLoading />;

  const yaraMatches = getYaraMatches(kit.analysis_results);

  const handleReanalyze = () => {
    reanalyze.mutate(id!, {
      onSuccess: () => toast.success("Re-analysis started"),
      onError: (err) => toast.error(err.message),
    });
  };

  const handleRedownload = () => {
    forceRedownload.mutate(
      { url: kit.source_url },
      {
        onSuccess: (data) => {
          setRedownloadOpen(false);
          toast.success("Re-download started", {
            action: {
              label: "View Kit",
              onClick: () => navigate(`/kits/${data.kit_id}`),
            },
          });
        },
        onError: (err) => toast.error(err.message),
      }
    );
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
          {kit.source_url && !kit.source_url.startsWith("file://") && (
            <Button variant="outline" size="sm" onClick={() => setRedownloadOpen(true)} disabled={forceRedownload.isPending}>
              <Download className="mr-2 h-4 w-4" />
              Re-download
            </Button>
          )}
          <Link to={`/phish-diff?a=${id}&mode=any`}>
            <Button variant="outline" size="sm">
              <FileDiff className="mr-2 h-4 w-4" />
              Compare
            </Button>
          </Link>
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
          <div>
            <span className="text-xs text-muted-foreground">TLSH</span>
            {kit.tlsh ? (
              <Link
                to={`/kits?search=${encodeURIComponent(`tlsh:${kit.tlsh}`)}`}
                className="font-mono text-xs break-all block hover:underline text-blue-400"
                title="Search for similar kits by TLSH"
              >
                {kit.tlsh}
                <Search className="inline ml-1 h-3 w-3" />
              </Link>
            ) : (
              <p className="font-mono text-xs break-all">—</p>
            )}
          </div>
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
            <p className="text-sm">{kit.file_size ? formatBytes(kit.file_size) : "—"}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Chain Depth</span>
            <p className="text-sm">{kit.chain_depth}</p>
          </div>
        </CardContent>
      </Card>

      {/* Pipeline progress */}
      {["analyzing", "analyzed", "failed"].includes(kit.status) && kit.analysis_results.length > 0 && (
        <AnalysisPipeline results={kit.analysis_results} status={kit.status} />
      )}

      {kit.error_message && (
        <Card className="border-red-500/30">
          <CardContent className="p-4">
            <p className="text-sm text-red-400 font-mono">{kit.error_message}</p>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="overflow-x-auto">
          <TabsTrigger value="indicators">
            Indicators ({kit.indicators.length})
          </TabsTrigger>
          <TabsTrigger value="yara">
            YARA ({yaraMatches.length})
          </TabsTrigger>
          <TabsTrigger value="analysis">
            Analysis ({kit.analysis_results.length})
          </TabsTrigger>
          <TabsTrigger value="screenshots">
            Screenshots ({screenshotsData?.screenshots.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="network">
            Network ({networkData?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="resources">
            Resources ({resourcesData?.resources.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="content">
            Content
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
          <TabsTrigger value="actors">
            Actors ({kitActors?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="families">
            Families ({kit.families?.length ?? 0})
          </TabsTrigger>
        </TabsList>

        {/* Indicators Tab */}
        <TabsContent value="indicators" className="mt-4">
          {kit.indicators.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No indicators extracted</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="whitespace-nowrap">Type</TableHead>
                  <TableHead className="w-full">Value</TableHead>
                  <TableHead className="whitespace-nowrap">Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {kit.indicators.map((ioc) => (
                  <TableRow key={ioc.id}>
                    <TableCell className="whitespace-nowrap">
                      <IocTypeBadge type={ioc.type} />
                    </TableCell>
                    <TableCell className="font-mono text-xs" style={{ maxWidth: 0 }}>
                      <div className="truncate" title={ioc.value}>{ioc.value}</div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
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

        {/* YARA Tab */}
        <TabsContent value="yara" className="mt-4">
          {yaraMatches.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No YARA matches</p>
          ) : (
            <div className="space-y-3">
              {yaraMatches.map((match, i) => (
                <Card key={`${match.rule}-${i}`}>
                  <CardContent className="p-4 space-y-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="default" className="font-mono">{match.rule}</Badge>
                      {match.namespace && match.namespace !== "default" && (
                        <Badge variant="secondary" className="text-xs">{match.namespace}</Badge>
                      )}
                      {match.tags?.map((tag) => (
                        <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                      ))}
                      <Link
                        to={`/kits?search=${encodeURIComponent(`yara:${match.rule}`)}`}
                        className="text-xs text-blue-400 hover:underline ml-auto flex items-center gap-1"
                      >
                        Find other kits <ExternalLink className="h-3 w-3" />
                      </Link>
                    </div>
                    {match.meta && Object.keys(match.meta).length > 0 && (
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-1 text-xs">
                        {Object.entries(match.meta).map(([k, v]) => (
                          <div key={k}>
                            <span className="text-muted-foreground">{k}:</span>{" "}
                            <span className="font-mono">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Analysis Tab */}
        <TabsContent value="analysis" className="mt-4">
          {kit.analysis_results.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No analysis results yet</p>
          ) : (
            <Accordion multiple className="space-y-2">
              {kit.analysis_results.map((result) => (
                <AccordionItem key={result.id} value={result.id} className="border rounded-md px-4">
                  <AccordionTrigger className="text-sm">
                    <div className="flex items-center gap-3 flex-wrap">
                      <Badge variant="secondary">{result.analysis_type}</Badge>
                      {result.error && (
                        <Badge variant="destructive" className="text-xs">error</Badge>
                      )}
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
                      <AnalysisSummary result={result} />
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    {result.error && (
                      <p className="text-sm text-red-400 font-mono mb-2">{result.error}</p>
                    )}
                    <AnalysisResultView result={result} kitId={id} />
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          )}
        </TabsContent>

        {/* Screenshots Tab */}
        <TabsContent value="screenshots" className="mt-4">
          <TabScreenshots kitId={id!} enabled={activeTab === "screenshots"} />
        </TabsContent>

        {/* Network Tab */}
        <TabsContent value="network" className="mt-4">
          <TabNetwork kitId={id!} enabled={activeTab === "network"} />
        </TabsContent>

        {/* Resources Tab */}
        <TabsContent value="resources" className="mt-4">
          <TabResources kitId={id!} enabled={activeTab === "resources"} />
        </TabsContent>

        {/* Content Tab */}
        <TabsContent value="content" className="mt-4">
          {contentLoading ? (
            <p className="text-sm text-muted-foreground py-8 text-center">Loading content...</p>
          ) : !contentData || contentData.files.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No text content available</p>
          ) : (
            <div className="space-y-3">
              {contentData.files.length > 1 && (
                <div className="flex flex-wrap gap-1">
                  {contentData.files.map((f, i) => (
                    <Button
                      key={f.filename}
                      variant={i === selectedFile ? "default" : "outline"}
                      size="sm"
                      className="text-xs font-mono"
                      onClick={() => setSelectedFile(i)}
                    >
                      {f.filename}
                    </Button>
                  ))}
                </div>
              )}
              <ContentViewer file={contentData.files[selectedFile]} />
            </div>
          )}
        </TabsContent>

        {/* Similar Tab */}
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

        {/* Children Tab */}
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

        {/* Campaigns Tab */}
        <TabsContent value="campaigns" className="mt-4 space-y-4">
          {kit.campaigns.length > 0 && (
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
          <div className="flex items-center gap-2">
            <select
              className="flex h-9 w-full max-w-xs rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
              value={selectedCampaignId}
              onChange={(e) => setSelectedCampaignId(e.target.value)}
            >
              <option value="">Select a campaign...</option>
              {(campaignsData?.items ?? [])
                .filter((c) => !kit.campaigns.some((kc) => kc.id === c.id))
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}{c.target_brand ? ` (${c.target_brand})` : ""}
                  </option>
                ))}
            </select>
            <Button
              size="sm"
              disabled={!selectedCampaignId || addToCampaign.isPending}
              onClick={() => {
                addToCampaign.mutate(
                  { kitId: id!, campaignId: selectedCampaignId },
                  {
                    onSuccess: (data) => {
                      if (data.used_root) {
                        toast.info(data.message);
                      } else {
                        toast.success("Kit added to campaign");
                      }
                      setSelectedCampaignId("");
                    },
                    onError: (err) => toast.error(err.message),
                  }
                );
              }}
            >
              <Plus className="mr-1 h-4 w-4" />
              {addToCampaign.isPending ? "Adding..." : "Add to Campaign"}
            </Button>
          </div>
          {kit.campaigns.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-4">Not linked to any campaigns yet</p>
          )}
        </TabsContent>

        {/* Actors Tab */}
        <TabsContent value="actors" className="mt-4 space-y-4">
          {(kitActors ?? []).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {kitActors!.map((a) => (
                <Link key={a.id} to={`/actors/${a.id}`}>
                  <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                    {a.name}
                  </Badge>
                </Link>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <select
              className="flex h-9 w-full max-w-xs rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
              value={selectedActorId}
              onChange={(e) => setSelectedActorId(e.target.value)}
            >
              <option value="">Select an actor...</option>
              {(actorsData?.items ?? []).map((a) => (
                <option key={a.id} value={a.id}>{a.name}</option>
              ))}
            </select>
            <Button
              size="sm"
              disabled={!selectedActorId || addToActor.isPending}
              onClick={() => {
                addToActor.mutate(
                  { kitId: id!, actorId: selectedActorId },
                  {
                    onSuccess: (data) => {
                      if (data.used_root) {
                        toast.info(data.message);
                      } else {
                        toast.success(`${data.linked} indicator(s) linked to actor`);
                      }
                      setSelectedActorId("");
                    },
                    onError: (err) => toast.error(err.message),
                  }
                );
              }}
            >
              <Plus className="mr-1 h-4 w-4" />
              {addToActor.isPending ? "Linking..." : "Link to Actor"}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Links all indicators from this kit (and its children) to the selected actor.
            {kit.parent_kit_id && " Since this is a child kit, the root kit's indicators will be linked instead."}
          </p>
        </TabsContent>

        {/* Families Tab */}
        <TabsContent value="families" className="mt-4 space-y-4">
          {(kit.families ?? []).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {kit.families.map((f) => (
                <Link key={f.id} to={`/families/${f.id}`}>
                  <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                    {f.name}
                  </Badge>
                </Link>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <select
              className="flex h-9 w-full max-w-xs rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
              value={selectedFamilyId}
              onChange={(e) => setSelectedFamilyId(e.target.value)}
            >
              <option value="">Select a family...</option>
              {(familiesData?.items ?? [])
                .filter((f) => !(kit.families ?? []).some((kf) => kf.id === f.id))
                .map((f) => (
                  <option key={f.id} value={f.id}>{f.name}</option>
                ))}
            </select>
            <Button
              size="sm"
              disabled={!selectedFamilyId || addToFamily.isPending}
              onClick={() => {
                addToFamily.mutate(
                  { kitId: id!, familyId: selectedFamilyId },
                  {
                    onSuccess: (data) => {
                      if (data.used_root) {
                        toast.info(data.message);
                      } else {
                        toast.success("Kit added to family");
                      }
                      setSelectedFamilyId("");
                    },
                    onError: (err) => toast.error(err.message),
                  }
                );
              }}
            >
              <Plus className="mr-1 h-4 w-4" />
              {addToFamily.isPending ? "Adding..." : "Add to Family"}
            </Button>
          </div>
          {(kit.families ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-4">Not linked to any families yet</p>
          )}
        </TabsContent>
      </Tabs>

      {/* Parent + Investigation links — full IDs */}
      {kit.parent_kit_id && (
        <div className="text-sm text-muted-foreground">
          Parent kit:{" "}
          <Link to={`/kits/${kit.parent_kit_id}`} className="font-mono text-xs hover:underline break-all">
            {kit.parent_kit_id}
          </Link>
        </div>
      )}

      {kit.investigation_id && (
        <div className="text-sm text-muted-foreground">
          Investigation:{" "}
          <Link to={`/investigations/${kit.investigation_id}`} className="font-mono text-xs hover:underline break-all">
            {kit.investigation_id}
          </Link>
        </div>
      )}

      {/* Re-download confirmation dialog */}
      <Dialog open={redownloadOpen} onOpenChange={setRedownloadOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Re-download Kit</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <p className="text-sm">
              This will create a <span className="font-medium">new kit</span> by re-downloading
              and re-analyzing the source URL:
            </p>
            <p className="font-mono text-xs text-muted-foreground break-all">{kit.source_url}</p>
            <p className="text-xs text-muted-foreground">
              The existing kit will not be modified. URL and hash deduplication checks will be skipped.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRedownloadOpen(false)}>Cancel</Button>
            <Button onClick={handleRedownload} disabled={forceRedownload.isPending}>
              {forceRedownload.isPending ? "Submitting..." : "Re-download"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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

// ── Sub-components ──

function HashField({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <span className="text-xs text-muted-foreground">{label}</span>
      <p className="font-mono text-xs break-all">{value ?? "—"}</p>
    </div>
  );
}

function AnalysisSummary({ result }: { result: AnalysisResultBrief }) {
  const data = result.result_data;
  if (!data) return null;

  switch (result.analysis_type) {
    case "yara_scan": {
      const count = (data.match_count as number) ?? (Array.isArray(data.matches) ? data.matches.length : 0);
      return count > 0 ? (
        <span className="text-xs text-yellow-400">{count} rule{count !== 1 ? "s" : ""} matched</span>
      ) : (
        <span className="text-xs text-muted-foreground">no matches</span>
      );
    }
    case "ioc_extraction": {
      const count = (data.iocs_extracted as number) ?? (data.total_iocs as number) ?? 0;
      return <span className="text-xs text-muted-foreground">{count} IOCs</span>;
    }
    case "similarity": {
      const count = (data.similar_count as number) ?? 0;
      return <span className="text-xs text-muted-foreground">{count} similar</span>;
    }
    case "hash": {
      return <span className="text-xs text-muted-foreground">hashes computed</span>;
    }
    case "deobfuscation": {
      const decoded = (data.decoded_count as number) ?? (data.files_decoded as number) ?? 0;
      return decoded > 0 ? (
        <span className="text-xs text-muted-foreground">{decoded} decoded</span>
      ) : null;
    }
    default:
      return null;
  }
}

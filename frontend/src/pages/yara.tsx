import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useKits } from "@/hooks/use-kits";
import {
  useDeleteUserRule,
  useSaveUserRule,
  useScannableFiles,
  useScanPlayground,
  useYaraRule,
  useYaraRules,
  useYaraStatus,
} from "@/hooks/use-yara";
import { YaraEditor } from "@/components/shared/yara-editor";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { Play, AlertTriangle, X, FileSearch, Trash2, Save, Upload } from "lucide-react";
import type {
  YaraKitTarget,
  YaraMatch,
  YaraPlaygroundRequest,
  YaraRawTarget,
  YaraScanOptions,
  YaraStringMatch,
} from "@/types/api";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const STARTER_RULE = `// Sample rule — edit me, then click Run.
//
// Targets: pick a stored kit on the right, paste a snippet in the
// "Paste" tab, or upload a file.  Save passing rules out to your
// team's rules repo when you're done — playground edits live in
// this browser tab only.
//
// Module imports (pe, dotnet, math, hash, …) are supported.
// 'include' directives are blocked.

rule example_phish {
    meta:
        author = "you"
        description = "starter playground rule"
    strings:
        $login = "Sign in to your account" nocase
        $kit_marker = /\\b(panel|admin|cpanel)\\b/
    condition:
        any of them
}
`;

const FILE_TYPE_PRESETS: { label: string; extensions: string[] }[] = [
  { label: "Web (HTML/JS/CSS)", extensions: ["html", "htm", "js", "css"] },
  { label: "Server (PHP/ASP/JSP)", extensions: ["php", "asp", "aspx", "jsp", "pl"] },
  { label: "Configs", extensions: ["conf", "ini", "htaccess", "yml", "yaml", "cfg", "json", "xml"] },
  { label: "Mail (EML/SVG)", extensions: ["eml", "svg"] },
  { label: "Scripts", extensions: ["py", "sh", "bat", "ps1", "vbs"] },
];

const HISTORY_KEY = "yara-playground-history-v1";
const HISTORY_LIMIT = 10;

interface HistoryEntry {
  ts: number;
  ruleSnippet: string;  // first line of rule, for display
  kitIds: string[];
  matches: number;
}

export function YaraPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialKit = searchParams.get("kit") || "";
  const initialRuleName = searchParams.get("rule") || "";

  const status = useYaraStatus();
  const loadedRule = useYaraRule(initialRuleName || null);

  const [ruleSource, setRuleSource] = useState(STARTER_RULE);
  const [activeRuleName, setActiveRuleName] = useState(initialRuleName);

  // Targets — multi-kit selection (Phase 1 supports list of kits)
  const [selectedKitIds, setSelectedKitIds] = useState<string[]>(initialKit ? [initialKit] : []);
  const [pasteName, setPasteName] = useState("paste.txt");
  const [pasteContent, setPasteContent] = useState("");
  const [uploads, setUploads] = useState<{ name: string; size: number; b64: string }[]>([]);
  const [targetTab, setTargetTab] = useState<"kits" | "paste" | "upload">("kits");

  // Save dialog
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [saveAsName, setSaveAsName] = useState("");
  const saveRule = useSaveUserRule();
  const deleteRule = useDeleteUserRule();

  // Options
  const [maxFiles, setMaxFiles] = useState(500);
  const [maxFileSizeMb, setMaxFileSizeMb] = useState(10);
  const [timeoutSeconds, setTimeoutSeconds] = useState(10);
  const [extensionsFilter, setExtensionsFilter] = useState<Set<string>>(new Set());

  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());

  // Hydrate editor when a saved rule loads.
  useEffect(() => {
    if (loadedRule.data?.content) {
      setRuleSource(loadedRule.data.content);
    }
  }, [loadedRule.data?.content]);

  const scan = useScanPlayground();

  const handleRun = async () => {
    if (!status.data?.available) {
      toast.error("yara-python is not installed in the API environment");
      return;
    }
    const kits: YaraKitTarget[] = selectedKitIds.map((id) => ({ kit_id: id }));
    const raw: YaraRawTarget[] = [];
    if (pasteContent.trim()) {
      raw.push({ name: pasteName || "paste.txt", content: pasteContent });
    }
    for (const u of uploads) {
      raw.push({ name: u.name, content_b64: u.b64 });
    }
    if (kits.length === 0 && raw.length === 0) {
      toast.error("Pick a kit, paste a snippet, or upload a file first");
      return;
    }

    const options: YaraScanOptions = {
      timeout_seconds: timeoutSeconds,
      max_files: maxFiles,
      max_file_size_mb: maxFileSizeMb,
      include_strings: true,
      string_context_bytes: 64,
      extensions: extensionsFilter.size ? Array.from(extensionsFilter) : undefined,
    };

    const req: YaraPlaygroundRequest = {
      rule_source: ruleSource,
      kits,
      raw,
      options,
    };

    try {
      const result = await scan.mutateAsync(req);
      if (!result.compile.ok) {
        toast.error("Rule failed to compile — see Errors tab");
      } else {
        toast.success(`Scan complete — ${result.matches.length} matches across ${result.stats.files_scanned} files`);
        const entry: HistoryEntry = {
          ts: Date.now(),
          ruleSnippet: ruleSource.split("\n").find((l) => l.trim().startsWith("rule "))?.slice(0, 64) || "(unnamed rule)",
          kitIds: selectedKitIds,
          matches: result.matches.length,
        };
        const next = [entry, ...history].slice(0, HISTORY_LIMIT);
        setHistory(next);
        saveHistory(next);
      }
    } catch (e) {
      toast.error(`Scan failed: ${(e as Error).message}`);
    }
  };

  const result = scan.data;

  // Inferred "current saved name" — only set when the loaded rule is a
  // user rule; built-in rules can't be overwritten so the Save button
  // becomes Save As.
  const currentUserRuleName =
    loadedRule.data?.source === "user" ? loadedRule.data.name : null;

  const handleSave = async (name: string) => {
    if (!name) {
      toast.error("Pick a name first");
      return;
    }
    try {
      const r = await saveRule.mutateAsync({ name, content: ruleSource });
      if (!r.compile_ok) {
        toast.error("Rule didn't compile — fix errors before saving");
        return;
      }
      toast.success(`Saved as user/${r.name}.yar`);
      setSaveDialogOpen(false);
      setSaveAsName("");
      setActiveRuleName(r.relative_path);
      setSearchParams((prev) => {
        const p = new URLSearchParams(prev);
        p.set("rule", r.relative_path);
        return p;
      });
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    }
  };

  const handleDelete = async () => {
    if (!currentUserRuleName) return;
    if (!confirm(`Delete user rule "${currentUserRuleName}"?`)) return;
    try {
      await deleteRule.mutateAsync(currentUserRuleName);
      toast.success(`Deleted user/${currentUserRuleName}.yar`);
      setActiveRuleName("");
      setRuleSource(STARTER_RULE);
      setSearchParams((prev) => {
        const p = new URLSearchParams(prev);
        p.delete("rule");
        return p;
      });
    } catch (e) {
      toast.error(`Delete failed: ${(e as Error).message}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Yara</h1>
          <p className="text-sm text-muted-foreground">
            Author and test YARA rules against stored kit files.
            {status.data && (
              <>
                {" "}<span className="opacity-70">
                  {status.data.available
                    ? `${status.data.builtin_rule_files} builtin · ${status.data.user_rule_files} user rule files`
                    : "yara-python not installed in API"}
                </span>
              </>
            )}
          </p>
        </div>
        <Button
          onClick={handleRun}
          disabled={scan.isPending || !status.data?.available}
        >
          <Play className="mr-2 h-4 w-4" />
          {scan.isPending ? "Scanning…" : "Run scan"}
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ── Editor pane ── */}
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
            <CardTitle className="text-base">Rule editor</CardTitle>
            <div className="flex items-center gap-2">
              <RulePicker
                activeName={activeRuleName}
                onPick={(name) => {
                  setActiveRuleName(name);
                  if (name) setSearchParams((prev) => {
                    const p = new URLSearchParams(prev);
                    p.set("rule", name);
                    return p;
                  });
                }}
              />
              {currentUserRuleName ? (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleSave(currentUserRuleName)}
                    disabled={saveRule.isPending}
                    title="Overwrite the current user rule"
                  >
                    <Save className="mr-1 h-3 w-3" /> Save
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={handleDelete}
                    disabled={deleteRule.isPending}
                    title="Delete this user rule"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </>
              ) : null}
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setSaveAsName(currentUserRuleName ?? "");
                  setSaveDialogOpen(true);
                }}
              >
                <Save className="mr-1 h-3 w-3" /> Save as…
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <YaraEditor value={ruleSource} onChange={setRuleSource} />
            <CompileStatus />
          </CardContent>
        </Card>

        <Dialog open={saveDialogOpen} onOpenChange={setSaveDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Save rule</DialogTitle>
            </DialogHeader>
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Saved to <code className="font-mono">rules/user/&lt;name&gt;.yar</code>.
                Letters, digits, <code>_</code> and <code>-</code> only; ≤ 64 chars.
                User rules are gitignored — copy out to the team rules repo to ship.
              </p>
              <Input
                placeholder="my_rule_name"
                value={saveAsName}
                onChange={(e) => setSaveAsName(e.target.value)}
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSave(saveAsName);
                }}
              />
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setSaveDialogOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => handleSave(saveAsName)}
                disabled={!saveAsName || saveRule.isPending}
              >
                Save
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* ── Targets pane ── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Targets</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs value={targetTab} onValueChange={(v) => setTargetTab(v as "kits" | "paste" | "upload")}>
              <TabsList>
                <TabsTrigger value="kits">Stored kits</TabsTrigger>
                <TabsTrigger value="paste">Paste</TabsTrigger>
                <TabsTrigger value="upload">Upload</TabsTrigger>
              </TabsList>
              <TabsContent value="kits" className="space-y-3 pt-2">
                <KitTargetPicker
                  selected={selectedKitIds}
                  onChange={setSelectedKitIds}
                />
              </TabsContent>
              <TabsContent value="paste" className="space-y-2 pt-2">
                <Input
                  placeholder="filename (e.g. snippet.html)"
                  value={pasteName}
                  onChange={(e) => setPasteName(e.target.value)}
                />
                <textarea
                  className="w-full min-h-[260px] rounded-md border border-border bg-background p-2 font-mono text-xs"
                  placeholder="Paste a snippet to scan…"
                  value={pasteContent}
                  onChange={(e) => setPasteContent(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Snippet is sent to the API per scan; not persisted server-side.
                </p>
              </TabsContent>
              <TabsContent value="upload" className="space-y-2 pt-2">
                <UploadTargetPicker uploads={uploads} onChange={setUploads} maxSizeMb={maxFileSizeMb} />
              </TabsContent>
            </Tabs>

            <div className="mt-4 space-y-2 border-t border-border pt-3">
              <div className="text-xs font-medium text-muted-foreground">Filters & limits</div>
              <FileTypeFilter selected={extensionsFilter} onChange={setExtensionsFilter} />
              <div className="grid grid-cols-3 gap-2">
                <NumberField label="Max files" value={maxFiles} setValue={setMaxFiles} min={1} max={5000} />
                <NumberField label="Max size (MB)" value={maxFileSizeMb} setValue={setMaxFileSizeMb} min={1} max={100} />
                <NumberField label="Timeout (s)" value={timeoutSeconds} setValue={setTimeoutSeconds} min={1} max={60} />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Results ── */}
      <ResultsPanel result={result ?? null} pending={scan.isPending} />

      {/* ── History ── */}
      {history.length > 0 && (
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
            <CardTitle className="text-base">Recent runs (this browser)</CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setHistory([]);
                saveHistory([]);
                toast.success("History cleared");
              }}
            >
              <Trash2 className="mr-1 h-3 w-3" /> Clear
            </Button>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-xs">
              {history.map((h, i) => (
                <li key={i} className="flex items-center justify-between gap-3 text-muted-foreground">
                  <span className="truncate font-mono">{h.ruleSnippet}</span>
                  <span className="shrink-0">
                    {h.matches} matches · {h.kitIds.length} kits · {new Date(h.ts).toLocaleTimeString()}
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );

  function CompileStatus() {
    if (!result) return null;
    const c = result.compile;
    if (c.ok) {
      return (
        <div className="text-xs text-muted-foreground">
          Compiled {c.rules_count} rule{c.rules_count === 1 ? "" : "s"}.
        </div>
      );
    }
    return (
      <div className="space-y-1 rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs">
        <div className="flex items-center gap-1 font-medium text-destructive">
          <AlertTriangle className="h-3 w-3" /> Compile errors
        </div>
        {c.errors.map((e, i) => (
          <div key={i} className="font-mono">
            {e.line ? `line ${e.line}${e.column ? `:${e.column}` : ""}: ` : ""}{e.message}
          </div>
        ))}
      </div>
    );
  }
}

// ── Sub-components ──

function RulePicker({ activeName, onPick }: { activeName: string; onPick: (name: string) => void }) {
  const { data: rules } = useYaraRules();
  if (!rules?.length) return null;
  // Sort: user first (most relevant for an analyst), then builtin, then third_party.
  const sortRank = (s: string) => (s === "user" ? 0 : s === "builtin" ? 1 : 2);
  const sorted = [...rules].sort(
    (a, b) => sortRank(a.source) - sortRank(b.source) || a.relative_path.localeCompare(b.relative_path),
  );
  return (
    <Select value={activeName || "__none__"} onValueChange={(v) => onPick(v === "__none__" ? "" : (v as string))}>
      <SelectTrigger size="sm" className="min-w-[220px]">
        <SelectValue placeholder="Load a rule…" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="__none__">— starter template —</SelectItem>
        {sorted.map((r) => (
          <SelectItem key={r.relative_path} value={r.relative_path}>
            <span className="font-mono text-xs">{r.relative_path}</span>
            <span className="ml-2 text-[10px] text-muted-foreground">
              {r.source === "user" ? "user" : r.source === "third_party" ? "t4d" : "builtin"} · {r.rule_count}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function KitTargetPicker({
  selected,
  onChange,
}: {
  selected: string[];
  onChange: (ids: string[]) => void;
}) {
  const [filter, setFilter] = useState("");
  const { data, isLoading } = useKits({ limit: 50, status_filter: "analyzed" });
  const items = data?.items ?? [];
  const filtered = filter
    ? items.filter((k) =>
        k.source_url.toLowerCase().includes(filter.toLowerCase()) ||
        (k.sha256 ?? "").toLowerCase().includes(filter.toLowerCase()),
      )
    : items;

  const toggle = (id: string) => {
    if (selected.includes(id)) onChange(selected.filter((x) => x !== id));
    else onChange([...selected, id]);
  };

  return (
    <div className="space-y-2">
      <Input
        placeholder="Filter kits by URL or SHA256…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {selected.map((id) => (
            <Badge key={id} variant="secondary" className="font-mono text-[10px]">
              {id.slice(0, 8)}
              <button
                type="button"
                onClick={() => toggle(id)}
                className="ml-1 opacity-70 hover:opacity-100"
                aria-label="Remove"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
      <ScrollArea className="h-[260px] rounded-md border border-border">
        {isLoading ? (
          <div className="p-3 text-xs text-muted-foreground">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="p-3 text-xs text-muted-foreground">No analyzed kits found.</div>
        ) : (
          <ul className="divide-y divide-border text-xs">
            {filtered.map((k) => {
              const checked = selected.includes(k.id);
              return (
                <li key={k.id}>
                  <button
                    type="button"
                    onClick={() => toggle(k.id)}
                    className={`flex w-full items-start gap-2 p-2 text-left transition-colors hover:bg-accent/40 ${checked ? "bg-accent/40" : ""}`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      readOnly
                      className="mt-0.5"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium">{k.source_url}</div>
                      <div className="truncate font-mono text-[10px] text-muted-foreground">
                        {k.sha256?.slice(0, 16) ?? "no sha256"}
                      </div>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </ScrollArea>
      {selected.length === 1 && <ScannableFilesPreview kitId={selected[0]} />}
    </div>
  );
}

function UploadTargetPicker({
  uploads,
  onChange,
  maxSizeMb,
}: {
  uploads: { name: string; size: number; b64: string }[];
  onChange: (next: { name: string; size: number; b64: string }[]) => void;
  maxSizeMb: number;
}) {
  const handleFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const next = [...uploads];
    for (const file of Array.from(files)) {
      if (file.size > maxSizeMb * 1024 * 1024) {
        toast.error(`${file.name} exceeds ${maxSizeMb} MB cap`);
        continue;
      }
      const buf = await file.arrayBuffer();
      const b64 = arrayBufferToBase64(buf);
      next.push({ name: file.name, size: file.size, b64 });
      if (next.length >= 20) {
        toast.warning("Upload tab capped at 20 files per scan");
        break;
      }
    }
    onChange(next);
  };

  return (
    <div className="space-y-2">
      <label className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border bg-muted/20 p-6 text-xs text-muted-foreground transition-colors hover:bg-muted/40 cursor-pointer">
        <Upload className="h-5 w-5" />
        <span>Click to choose files (up to {maxSizeMb} MB each, 20 max per scan)</span>
        <span className="text-[10px] opacity-60">
          Files are read in your browser and sent base64-encoded with the scan request.
          Nothing is persisted server-side.
        </span>
        <input
          type="file"
          multiple
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />
      </label>
      {uploads.length > 0 && (
        <ul className="divide-y divide-border rounded-md border border-border text-xs">
          {uploads.map((u, i) => (
            <li key={i} className="flex items-center justify-between gap-2 p-2">
              <div className="flex min-w-0 flex-col">
                <span className="truncate font-mono">{u.name}</span>
                <span className="text-[10px] text-muted-foreground">{formatBytes(u.size)}</span>
              </div>
              <button
                type="button"
                onClick={() => onChange(uploads.filter((_, j) => j !== i))}
                className="opacity-70 hover:opacity-100"
                aria-label="Remove"
              >
                <X className="h-3 w-3" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  // Avoid String.fromCharCode(...new Uint8Array(buf)) which blows the
  // call-stack on multi-MB buffers.  Chunk into 32 KB pieces.
  const bytes = new Uint8Array(buf);
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, Math.min(i + CHUNK, bytes.length));
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function ScannableFilesPreview({ kitId }: { kitId: string }) {
  const { data } = useScannableFiles(kitId);
  if (!data) return null;
  return (
    <div className="rounded-md border border-border p-2 text-[11px] text-muted-foreground">
      <div className="flex items-center gap-1">
        <FileSearch className="h-3 w-3" />
        Kit has <span className="font-medium text-foreground">{data.scannable_count}</span> scannable
        files (of {data.total} total).
      </div>
    </div>
  );
}

function FileTypeFilter({
  selected,
  onChange,
}: {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}) {
  const togglePreset = (exts: string[]) => {
    const next = new Set(selected);
    const allOn = exts.every((e) => next.has(e));
    if (allOn) exts.forEach((e) => next.delete(e));
    else exts.forEach((e) => next.add(e));
    onChange(next);
  };

  return (
    <div className="flex flex-wrap gap-1">
      <Badge
        variant={selected.size === 0 ? "default" : "outline"}
        className="cursor-pointer"
        onClick={() => onChange(new Set())}
      >
        All scannable
      </Badge>
      {FILE_TYPE_PRESETS.map((preset) => {
        const allOn = preset.extensions.every((e) => selected.has(e));
        return (
          <Badge
            key={preset.label}
            variant={allOn ? "default" : "outline"}
            className="cursor-pointer"
            onClick={() => togglePreset(preset.extensions)}
          >
            {preset.label}
          </Badge>
        );
      })}
    </div>
  );
}

function NumberField({
  label,
  value,
  setValue,
  min,
  max,
}: {
  label: string;
  value: number;
  setValue: (n: number) => void;
  min: number;
  max: number;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <Input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(e) => {
          const n = Number(e.target.value);
          if (Number.isFinite(n)) setValue(Math.max(min, Math.min(max, n)));
        }}
      />
    </label>
  );
}

function ResultsPanel({
  result,
  pending,
}: {
  result: import("@/types/api").YaraPlaygroundResponse | null;
  pending: boolean;
}) {
  const [tab, setTab] = useState<"matches" | "errors" | "raw">("matches");
  const matches = result?.matches ?? [];
  const errors = result?.target_errors ?? [];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Results</CardTitle>
      </CardHeader>
      <CardContent>
        {pending && (
          <div className="py-8 text-center text-sm text-muted-foreground">Scanning…</div>
        )}
        {!pending && !result && (
          <div className="py-8 text-center text-sm text-muted-foreground">
            Click <strong>Run scan</strong> to test your rule.
          </div>
        )}
        {!pending && result && (
          <>
            <div className="mb-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
              <Badge variant="secondary">{result.stats.files_scanned} files scanned</Badge>
              <Badge variant="secondary">{result.stats.files_skipped} skipped</Badge>
              <Badge variant="secondary">
                {(result.stats.bytes_scanned / 1024).toFixed(1)} KB
              </Badge>
              <Badge variant="secondary">{result.stats.duration_ms} ms</Badge>
              <Badge variant={matches.length > 0 ? "default" : "outline"}>
                {matches.length} matches
              </Badge>
              {errors.length > 0 && (
                <Badge variant="destructive">{errors.length} target errors</Badge>
              )}
            </div>
            <Tabs value={tab} onValueChange={(v) => setTab(v as "matches" | "errors" | "raw")}>
              <TabsList>
                <TabsTrigger value="matches">Matches ({matches.length})</TabsTrigger>
                <TabsTrigger value="errors">Errors ({errors.length})</TabsTrigger>
                <TabsTrigger value="raw">Raw JSON</TabsTrigger>
              </TabsList>
              <TabsContent value="matches">
                <MatchesTable matches={matches} />
              </TabsContent>
              <TabsContent value="errors">
                <ErrorsList errors={errors} compileErrors={result.compile.errors} />
              </TabsContent>
              <TabsContent value="raw">
                <pre className="max-h-[400px] overflow-auto rounded-md border border-border bg-muted/40 p-2 text-[11px]">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </TabsContent>
            </Tabs>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function MatchesTable({ matches }: { matches: YaraMatch[] }) {
  if (matches.length === 0) {
    return (
      <div className="py-6 text-center text-sm text-muted-foreground">
        No matches against the selected targets.
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Rule</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Tags</TableHead>
            <TableHead>Strings</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {matches.map((m, i) => (
            <MatchRow key={i} match={m} />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function MatchRow({ match }: { match: YaraMatch }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setOpen((o) => !o)}>
        <TableCell className="font-mono text-xs">{match.rule}</TableCell>
        <TableCell className="font-mono text-xs">
          <div className="flex flex-col">
            <span>{match.target_path}</span>
            {match.target_kit_id && (
              <span className="text-[10px] text-muted-foreground">
                kit {match.target_kit_id.slice(0, 8)}
              </span>
            )}
          </div>
        </TableCell>
        <TableCell>
          <div className="flex flex-wrap gap-1">
            {match.tags.map((tg) => (
              <Badge key={tg} variant="outline" className="text-[10px]">{tg}</Badge>
            ))}
          </div>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {match.strings.length} string{match.strings.length === 1 ? "" : "s"}
        </TableCell>
      </TableRow>
      {open && match.strings.length > 0 && (
        <TableRow>
          <TableCell colSpan={4} className="bg-muted/30">
            <ul className="space-y-1 font-mono text-[11px]">
              {match.strings.map((s: YaraStringMatch, i) => (
                <li key={i}>
                  <span className="text-muted-foreground">@{s.offset.toString(16)} {s.identifier}:</span>{" "}
                  <span className="opacity-60">{escapePreview(s.context_before)}</span>
                  <span className="bg-yellow-500/30 px-0.5">{escapePreview(s.matched)}</span>
                  <span className="opacity-60">{escapePreview(s.context_after)}</span>
                </li>
              ))}
            </ul>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function ErrorsList({
  errors,
  compileErrors,
}: {
  errors: import("@/types/api").YaraTargetError[];
  compileErrors: import("@/types/api").YaraCompileError[];
}) {
  if (errors.length === 0 && compileErrors.length === 0) {
    return <div className="py-4 text-sm text-muted-foreground">No errors.</div>;
  }
  return (
    <div className="space-y-3 text-xs">
      {compileErrors.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Compile</div>
          <ul className="space-y-1 font-mono">
            {compileErrors.map((e, i) => (
              <li key={i}>
                {e.line ? `line ${e.line}${e.column ? `:${e.column}` : ""}: ` : ""}{e.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      {errors.length > 0 && (
        <div>
          <div className="mb-1 font-medium">Targets</div>
          <ul className="space-y-1 font-mono">
            {errors.map((e, i) => (
              <li key={i}>
                <span className="text-muted-foreground">{e.target}:</span> {e.error}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Helpers ──

function escapePreview(s: string): string {
  // Collapse newlines/tabs to spaces and trim runs, so the inline match
  // preview stays on one line.  Matches retain their characters but are
  // capped at 256 bytes by the server.
  return s.replace(/[\r\n\t]+/g, " ").slice(0, 200);
}

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, HISTORY_LIMIT) : [];
  } catch {
    return [];
  }
}

function saveHistory(history: HistoryEntry[]) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    // Ignore quota / privacy-mode failures.
  }
}


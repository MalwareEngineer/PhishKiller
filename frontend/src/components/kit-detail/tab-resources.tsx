import { useState } from "react";
import { useKitBrowserResources } from "@/hooks/use-kits";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { FileCode, FileJson, FileType, File } from "lucide-react";

interface Props {
  kitId: string;
  enabled: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileIcon(filename: string) {
  const ext = filename.split(".").pop()?.toLowerCase();
  const cls = "h-4 w-4 text-muted-foreground";
  switch (ext) {
    case "js":
    case "php":
    case "html":
    case "htm":
    case "css":
      return <FileCode className={cls} />;
    case "json":
      return <FileJson className={cls} />;
    case "svg":
    case "xml":
      return <FileType className={cls} />;
    default:
      return <File className={cls} />;
  }
}

export function TabResources({ kitId, enabled }: Props) {
  const { data, isLoading } = useKitBrowserResources(kitId, enabled);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-8 text-center">Loading resources...</p>;
  }

  const resources = data?.resources ?? [];

  if (resources.length === 0) {
    return <p className="text-sm text-muted-foreground py-8 text-center">No browser resources captured</p>;
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        {resources.length} sub-resource{resources.length !== 1 ? "s" : ""} captured during browser rendering
      </p>
      <div className="max-h-[600px] overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-full">Filename</TableHead>
              <TableHead className="w-[80px]">Size</TableHead>
              <TableHead className="w-[140px]">MIME Type</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {resources.map((res, i) => (
              <>
                <TableRow
                  key={res.filename}
                  className={`cursor-pointer hover:bg-muted/50 ${res.content ? "" : "opacity-70"}`}
                  onClick={() => res.content ? setExpandedRow(expandedRow === i ? null : i) : undefined}
                >
                  <TableCell className="font-mono text-xs">
                    <div className="flex items-center gap-2">
                      {fileIcon(res.filename)}
                      <span className="truncate" title={res.filename}>{res.filename}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatBytes(res.size)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    <div className="flex items-center gap-1.5">
                      {res.mime_type ?? "—"}
                      {res.truncated && (
                        <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/30">
                          truncated
                        </Badge>
                      )}
                      {!res.content && (
                        <span className="text-[10px] text-muted-foreground/50">binary</span>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
                {expandedRow === i && res.content && (
                  <TableRow key={`${res.filename}-content`}>
                    <TableCell colSpan={3} className="bg-muted/30 p-0">
                      <pre className="text-[11px] font-mono leading-5 p-3 overflow-auto max-h-[600px] m-0 whitespace-pre">
                        {res.content}
                      </pre>
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

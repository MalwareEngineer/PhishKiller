import { useState } from "react";
import { useKitScreenshots } from "@/hooks/use-kits";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ChevronLeft, ChevronRight } from "lucide-react";

interface Props {
  kitId: string;
  enabled: boolean;
}

export function TabScreenshots({ kitId, enabled }: Props) {
  const { data, isLoading } = useKitScreenshots(kitId, enabled);
  const [viewIndex, setViewIndex] = useState<number | null>(null);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-8 text-center">Loading screenshots...</p>;
  }

  const screenshots = data?.screenshots ?? [];

  if (screenshots.length === 0) {
    return <p className="text-sm text-muted-foreground py-8 text-center">No screenshots captured</p>;
  }

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {screenshots.map((ss, i) => (
          <Card
            key={ss.filename}
            className="cursor-pointer hover:ring-1 hover:ring-ring transition-shadow overflow-hidden"
            onClick={() => setViewIndex(i)}
          >
            <div className="aspect-video bg-black/50 flex items-center justify-center overflow-hidden">
              <img
                src={ss.data_uri}
                alt={ss.stage}
                className="w-full h-full object-contain"
                loading="lazy"
              />
            </div>
            <CardContent className="p-3">
              <p className="text-sm font-medium">{ss.stage}</p>
              <p className="text-xs text-muted-foreground font-mono">{ss.filename}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Dialog open={viewIndex !== null} onOpenChange={() => setViewIndex(null)}>
        <DialogContent className="sm:max-w-5xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle>
              {viewIndex !== null ? screenshots[viewIndex]?.stage : "Screenshot"}
            </DialogTitle>
          </DialogHeader>
          {viewIndex !== null && (
            <div className="relative flex items-center justify-center">
              {screenshots.length > 1 && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="absolute left-0 z-10"
                  onClick={() => setViewIndex((viewIndex - 1 + screenshots.length) % screenshots.length)}
                >
                  <ChevronLeft className="h-5 w-5" />
                </Button>
              )}
              <img
                src={screenshots[viewIndex].data_uri}
                alt={screenshots[viewIndex].stage}
                className="max-h-[75vh] object-contain rounded"
              />
              {screenshots.length > 1 && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="absolute right-0 z-10"
                  onClick={() => setViewIndex((viewIndex + 1) % screenshots.length)}
                >
                  <ChevronRight className="h-5 w-5" />
                </Button>
              )}
            </div>
          )}
          {viewIndex !== null && screenshots.length > 1 && (
            <div className="flex justify-center gap-1.5 pt-2">
              {screenshots.map((_, i) => (
                <button
                  key={i}
                  className={`w-2 h-2 rounded-full transition-colors ${
                    i === viewIndex ? "bg-foreground" : "bg-muted-foreground/30"
                  }`}
                  onClick={() => setViewIndex(i)}
                />
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

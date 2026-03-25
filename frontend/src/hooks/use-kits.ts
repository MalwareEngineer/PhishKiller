import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { kits } from "@/lib/api";
import type { KitStatus } from "@/types/api";

export function useKits(params?: { offset?: number; limit?: number; status_filter?: KitStatus; source_feed?: string }) {
  return useQuery({
    queryKey: ["kits", params],
    queryFn: () => kits.list(params),
  });
}

export function useKit(id: string) {
  return useQuery({
    queryKey: ["kit", id],
    queryFn: () => kits.get(id),
    enabled: !!id,
  });
}

export function useKitActors(id: string) {
  return useQuery({
    queryKey: ["kit-actors", id],
    queryFn: () => kits.actors(id),
    enabled: !!id,
  });
}

export function useKitSimilar(id: string, threshold?: number) {
  return useQuery({
    queryKey: ["kit-similar", id, threshold],
    queryFn: () => kits.similar(id, threshold),
    enabled: !!id,
  });
}

export function useKitIndicators(id: string, offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["kit-indicators", id, offset, limit],
    queryFn: () => kits.indicators(id, offset, limit),
    enabled: !!id,
  });
}

export function useSubmitKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ url, source_feed }: { url: string; source_feed?: string }) =>
      kits.submit(url, source_feed),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kits"] }),
  });
}

export function useUploadKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, source_feed }: { file: File; source_feed?: string }) =>
      kits.upload(file, source_feed),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kits"] }),
  });
}

export function useBulkSubmitKits() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (urls: string[]) => kits.bulkSubmit(urls),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kits"] }),
  });
}

export function useBulkUploadKits() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (files: File[]) => kits.bulkUpload(files),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kits"] }),
  });
}

export function useReanalyzeKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => kits.reanalyze(id),
    onSuccess: (_data, id) => qc.invalidateQueries({ queryKey: ["kit", id] }),
  });
}

export function useKitDeletePreview(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ["kit-delete-preview", id],
    queryFn: () => kits.deletePreview(id),
    enabled: !!id && enabled,
  });
}

export function useKitContent(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ["kit-content", id],
    queryFn: () => kits.content(id),
    enabled: !!id && enabled,
  });
}

export function useSearchKits(params: {
  q?: string;
  yara_rule?: string;
  tlsh?: string;
  tlsh_threshold?: number;
  offset?: number;
  limit?: number;
}, enabled: boolean) {
  return useQuery({
    queryKey: ["kit-search", params],
    queryFn: () => kits.search(params),
    enabled,
  });
}

export function useDeleteKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => kits.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["kits"] });
      qc.invalidateQueries({ queryKey: ["investigations"] });
    },
  });
}

export function useAddKitToCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ kitId, campaignId }: { kitId: string; campaignId: string }) =>
      kits.addToCampaign(kitId, campaignId),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["kit", vars.kitId] });
      qc.invalidateQueries({ queryKey: ["campaigns"] });
    },
  });
}

export function useAddKitToActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ kitId, actorId }: { kitId: string; actorId: string }) =>
      kits.addToActor(kitId, actorId),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["kit", vars.kitId] });
      qc.invalidateQueries({ queryKey: ["kit-actors", vars.kitId] });
      qc.invalidateQueries({ queryKey: ["actors"] });
    },
  });
}

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { investigations } from "@/lib/api";

export function useInvestigations(offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["investigations", offset, limit],
    queryFn: () => investigations.list(offset, limit),
  });
}

export function useInvestigation(id: string) {
  return useQuery({
    queryKey: ["investigation", id],
    queryFn: () => investigations.get(id),
    enabled: !!id,
  });
}

export function useInvestigationTree(id: string) {
  return useQuery({
    queryKey: ["investigation-tree", id],
    queryFn: () => investigations.tree(id),
    enabled: !!id,
  });
}

export function useInvestigationKits(id: string, offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["investigation-kits", id, offset, limit],
    queryFn: () => investigations.kits(id, offset, limit),
    enabled: !!id,
  });
}

export function useCreateInvestigation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ url, max_depth }: { url: string; max_depth?: number }) =>
      investigations.create(url, max_depth),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["investigations"] }),
  });
}

export function useUpdateInvestigation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string; description?: string }) =>
      investigations.update(id, data),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["investigation", vars.id] });
      qc.invalidateQueries({ queryKey: ["investigations"] });
    },
  });
}

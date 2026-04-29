import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { families } from "@/lib/api";

export function useFamilies(offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["families", offset, limit],
    queryFn: () => families.list(offset, limit),
  });
}

export function useFamily(id: string) {
  return useQuery({
    queryKey: ["family", id],
    queryFn: () => families.get(id),
    enabled: !!id,
  });
}

export function useCreateFamily() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; aliases?: string[]; description?: string }) =>
      families.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["families"] }),
  });
}

export function useUpdateFamily() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      families.update(id, data),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["family", vars.id] });
      qc.invalidateQueries({ queryKey: ["families"] });
    },
  });
}

export function useDeleteFamily() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => families.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["families"] }),
  });
}

// ── Detail-page tab hooks ──

export function useFamilyStats(id: string | undefined) {
  return useQuery({
    queryKey: ["family", id, "stats"],
    queryFn: () => families.stats(id!),
    enabled: !!id,
  });
}

export function useFamilyKits(
  id: string | undefined,
  params?: { offset?: number; limit?: number; status?: string },
) {
  return useQuery({
    queryKey: [
      "family", id, "kits",
      params?.offset ?? 0,
      params?.limit ?? 25,
      params?.status ?? "",
    ],
    queryFn: () => families.kits(id!, params),
    enabled: !!id,
  });
}

export function useFamilyIndicators(
  id: string | undefined,
  offset = 0,
  limit = 25,
) {
  return useQuery({
    queryKey: ["family", id, "indicators", offset, limit],
    queryFn: () => families.indicators(id!, offset, limit),
    enabled: !!id,
  });
}

export function useFamilyYaraRules(id: string | undefined) {
  return useQuery({
    queryKey: ["family", id, "yara-rules"],
    queryFn: () => families.yaraRules(id!),
    enabled: !!id,
  });
}

export function useFamilyActors(id: string | undefined) {
  return useQuery({
    queryKey: ["family", id, "actors-list"],
    queryFn: () => families.actors(id!),
    enabled: !!id,
  });
}

export function useFamilyCampaigns(id: string | undefined) {
  return useQuery({
    queryKey: ["family", id, "campaigns"],
    queryFn: () => families.campaigns(id!),
    enabled: !!id,
  });
}

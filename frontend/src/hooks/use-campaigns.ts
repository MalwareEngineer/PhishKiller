import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { campaigns } from "@/lib/api";

export function useCampaigns(params?: { offset?: number; limit?: number; target_brand?: string }) {
  return useQuery({
    queryKey: ["campaigns", params],
    queryFn: () => campaigns.list(params),
  });
}

export function useCampaign(id: string) {
  return useQuery({
    queryKey: ["campaign", id],
    queryFn: () => campaigns.get(id),
    enabled: !!id,
  });
}

export function useCreateCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; description?: string; target_brand?: string }) =>
      campaigns.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["campaigns"] }),
  });
}

export function useUpdateCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      campaigns.update(id, data),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["campaign", vars.id] });
      qc.invalidateQueries({ queryKey: ["campaigns"] });
    },
  });
}

export function useDeleteCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => campaigns.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["campaigns"] }),
  });
}

export function useAddKitsToCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ campaignId, kitIds }: { campaignId: string; kitIds: string[] }) =>
      campaigns.addKits(campaignId, kitIds),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["campaigns"] });
      qc.invalidateQueries({ queryKey: ["kit"] });
    },
  });
}

// ── Detail-page tab hooks ──

export function useCampaignStats(id: string | undefined) {
  return useQuery({
    queryKey: ["campaign", id, "stats"],
    queryFn: () => campaigns.stats(id!),
    enabled: !!id,
  });
}

export function useCampaignKits(
  id: string | undefined,
  params?: { offset?: number; limit?: number; status?: string },
) {
  return useQuery({
    queryKey: [
      "campaign", id, "kits",
      params?.offset ?? 0,
      params?.limit ?? 25,
      params?.status ?? "",
    ],
    queryFn: () => campaigns.kits(id!, params),
    enabled: !!id,
  });
}

export function useCampaignIndicators(
  id: string | undefined,
  offset = 0,
  limit = 25,
) {
  return useQuery({
    queryKey: ["campaign", id, "indicators", offset, limit],
    queryFn: () => campaigns.indicators(id!, offset, limit),
    enabled: !!id,
  });
}

export function useCampaignVictims(
  id: string | undefined,
  offset = 0,
  limit = 25,
) {
  return useQuery({
    queryKey: ["campaign", id, "victims", offset, limit],
    queryFn: () => campaigns.victims(id!, offset, limit),
    enabled: !!id,
  });
}

export function useCampaignActors(id: string | undefined) {
  return useQuery({
    queryKey: ["campaign", id, "actors"],
    queryFn: () => campaigns.actors(id!),
    enabled: !!id,
  });
}

export function useCampaignFamilies(id: string | undefined) {
  return useQuery({
    queryKey: ["campaign", id, "families"],
    queryFn: () => campaigns.families(id!),
    enabled: !!id,
  });
}

export function useCampaignYaraRules(id: string | undefined) {
  return useQuery({
    queryKey: ["campaign", id, "yara-rules"],
    queryFn: () => campaigns.yaraRules(id!),
    enabled: !!id,
  });
}

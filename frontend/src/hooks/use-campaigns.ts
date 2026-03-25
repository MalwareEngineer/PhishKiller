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
    mutationFn: ({ id, ...data }: { id: string; description?: string; name?: string; target_brand?: string }) =>
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

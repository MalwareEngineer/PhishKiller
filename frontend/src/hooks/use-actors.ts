import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { actors } from "@/lib/api";

export function useActors(offset = 0, limit = 50) {
  return useQuery({
    queryKey: ["actors", offset, limit],
    queryFn: () => actors.list(offset, limit),
  });
}

export function useActor(id: string) {
  return useQuery({
    queryKey: ["actor", id],
    queryFn: () => actors.get(id),
    enabled: !!id,
  });
}

export function useCreateActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; aliases?: string[]; description?: string; email_addresses?: string[]; telegram_handles?: string[] }) =>
      actors.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actors"] }),
  });
}

export function useUpdateActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      actors.update(id, data),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["actor", vars.id] });
      qc.invalidateQueries({ queryKey: ["actors"] });
    },
  });
}

export function useDeleteActor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => actors.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actors"] }),
  });
}

export function useActorStats(id: string | undefined) {
  return useQuery({
    queryKey: ["actor", id, "stats"],
    queryFn: () => actors.stats(id!),
    enabled: !!id,
  });
}

export function useActorKits(
  id: string | undefined,
  params?: { offset?: number; limit?: number; status?: string },
) {
  return useQuery({
    queryKey: [
      "actor", id, "kits",
      params?.offset ?? 0,
      params?.limit ?? 25,
      params?.status ?? "",
    ],
    queryFn: () => actors.kits(id!, params),
    enabled: !!id,
  });
}

export function useActorIndicators(
  id: string | undefined,
  offset = 0,
  limit = 25,
) {
  return useQuery({
    queryKey: ["actor", id, "indicators", offset, limit],
    queryFn: () => actors.indicators(id!, offset, limit),
    enabled: !!id,
  });
}

export function useActorCampaigns(id: string | undefined) {
  return useQuery({
    queryKey: ["actor", id, "campaigns"],
    queryFn: () => actors.campaigns(id!),
    enabled: !!id,
  });
}

export function useActorFamilies(id: string | undefined) {
  return useQuery({
    queryKey: ["actor", id, "families"],
    queryFn: () => actors.families(id!),
    enabled: !!id,
  });
}

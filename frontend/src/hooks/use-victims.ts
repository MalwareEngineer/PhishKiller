import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { victims } from "@/lib/api";
import type { VictimType } from "@/types/api";

interface VictimsListParams {
  offset?: number;
  limit?: number;
  domain?: string;
  type?: VictimType;
  search?: string;
}

export function useVictims(params?: VictimsListParams) {
  return useQuery({
    // The query key intentionally enumerates each filter rather than
    // hashing the whole object so React Query's cache invalidates
    // predictably when one filter changes (and we don't keep stale
    // results from a different filter mix).
    queryKey: [
      "victims",
      params?.offset ?? 0,
      params?.limit ?? 25,
      params?.domain ?? "",
      params?.type ?? "",
      params?.search ?? "",
    ],
    queryFn: () => victims.list(params),
  });
}

export function useVictim(id: string | undefined) {
  return useQuery({
    queryKey: ["victim", id],
    queryFn: () => victims.get(id!),
    enabled: !!id,
  });
}

export function useUpdateVictim() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...data
    }: {
      id: string;
      display_name?: string | null;
      type?: VictimType;
      notes?: string | null;
    }) => victims.update(id, data),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["victim", vars.id] });
      qc.invalidateQueries({ queryKey: ["victims"] });
    },
  });
}

export function useVictimObservations(
  id: string | undefined,
  offset = 0,
  limit = 100,
) {
  return useQuery({
    queryKey: ["victim", id, "observations", offset, limit],
    queryFn: () => victims.observations(id!, offset, limit),
    enabled: !!id,
  });
}

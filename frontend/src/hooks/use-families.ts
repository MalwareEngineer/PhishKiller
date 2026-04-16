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

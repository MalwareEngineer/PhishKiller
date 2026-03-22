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

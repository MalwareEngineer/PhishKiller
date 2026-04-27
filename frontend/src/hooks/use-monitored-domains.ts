import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { monitoredDomains } from "@/lib/api";

export function useMonitoredDomains(offset = 0, limit = 200) {
  return useQuery({
    queryKey: ["monitored-domains", offset, limit],
    queryFn: () => monitoredDomains.list(offset, limit),
  });
}

export function useCreateMonitoredDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { domain: string; description?: string }) =>
      monitoredDomains.create(data),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["monitored-domains"] }),
  });
}

export function useUpdateMonitoredDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...data
    }: {
      id: string;
      domain?: string;
      description?: string | null;
    }) => monitoredDomains.update(id, data),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["monitored-domains"] }),
  });
}

export function useDeleteMonitoredDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => monitoredDomains.delete(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["monitored-domains"] }),
  });
}

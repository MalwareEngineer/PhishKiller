import { useQuery, useMutation } from "@tanstack/react-query";
import { feeds } from "@/lib/api";

export function useFeedEntries(params?: { offset?: number; limit?: number; source?: string; processed?: boolean }) {
  return useQuery({
    queryKey: ["feed-entries", params],
    queryFn: () => feeds.entries(params),
  });
}

export function useFeedStats() {
  return useQuery({
    queryKey: ["feed-stats"],
    queryFn: () => feeds.stats(),
  });
}

export function useIngestFeeds() {
  return useMutation({
    mutationFn: (source?: string) => feeds.ingest(source),
  });
}

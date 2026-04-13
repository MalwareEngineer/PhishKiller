import { useQuery } from "@tanstack/react-query";
import { diff } from "@/lib/api";

export function useDiffPairGroups(params?: {
  offset?: number;
  limit?: number;
  max_distance?: number;
  max_size_ratio?: number;
}) {
  return useQuery({
    queryKey: ["diff-pair-groups", params],
    queryFn: () => diff.pairGroups(params),
  });
}

export function useDiffPairs(kitId: string | undefined) {
  return useQuery({
    queryKey: ["diff-pairs", kitId],
    queryFn: () => diff.pairs(kitId!),
    enabled: !!kitId,
  });
}

export function useDiffCompare(
  kitAId: string | undefined,
  kitBId: string | undefined,
  normalize = false,
) {
  return useQuery({
    queryKey: ["diff-compare", kitAId, kitBId, normalize],
    queryFn: () => diff.compare(kitAId!, kitBId!, normalize),
    enabled: !!kitAId && !!kitBId,
  });
}

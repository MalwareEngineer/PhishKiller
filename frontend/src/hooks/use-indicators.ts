import { useQuery } from "@tanstack/react-query";
import { indicators } from "@/lib/api";
import type { IndicatorType } from "@/types/api";

export function useIndicators(params?: { offset?: number; limit?: number; type_filter?: IndicatorType }) {
  return useQuery({
    queryKey: ["indicators", params],
    queryFn: () => indicators.list(params),
  });
}

export function useIndicatorSearch(query: string, params?: { offset?: number; limit?: number; type_filter?: IndicatorType }) {
  return useQuery({
    queryKey: ["indicators-search", query, params],
    queryFn: () => indicators.search(query, params),
    enabled: query.length > 0,
  });
}

export function useIndicatorStats() {
  return useQuery({
    queryKey: ["indicator-stats"],
    queryFn: () => indicators.stats(),
  });
}

export function useIndicator(id: string) {
  return useQuery({
    queryKey: ["indicator", id],
    queryFn: () => indicators.get(id),
    enabled: !!id,
  });
}

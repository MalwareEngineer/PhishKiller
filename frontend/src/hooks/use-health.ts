import { useQuery } from "@tanstack/react-query";
import { health } from "@/lib/api";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => health.check(),
    refetchInterval: 30000,
  });
}

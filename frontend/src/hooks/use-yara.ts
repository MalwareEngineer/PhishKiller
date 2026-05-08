import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { yara } from "@/lib/api";
import type { YaraPlaygroundRequest } from "@/types/api";

export function useYaraStatus() {
  return useQuery({
    queryKey: ["yara", "status"],
    queryFn: () => yara.status(),
    staleTime: 60_000,
  });
}

export function useYaraRules() {
  return useQuery({
    queryKey: ["yara", "rules"],
    queryFn: () => yara.rules(),
    staleTime: 30_000,
  });
}

export function useYaraRule(name: string | null) {
  return useQuery({
    queryKey: ["yara", "rule", name],
    queryFn: () => yara.rule(name!),
    enabled: !!name,
  });
}

export function useScannableFiles(kitId: string | null) {
  return useQuery({
    queryKey: ["yara", "scannable-files", kitId],
    queryFn: () => yara.scannableFiles(kitId!),
    enabled: !!kitId,
  });
}

export function useCompileRule() {
  return useMutation({
    mutationFn: (rule_source: string) => yara.compile(rule_source),
  });
}

export function useScanPlayground() {
  return useMutation({
    mutationFn: (req: YaraPlaygroundRequest) => yara.playground(req),
  });
}

export function useSaveUserRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, content }: { name: string; content: string }) =>
      yara.saveUserRule(name, content),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["yara", "rules"] });
      qc.invalidateQueries({ queryKey: ["yara", "rule", data.relative_path] });
      qc.invalidateQueries({ queryKey: ["yara", "status"] });
    },
  });
}

export function useDeleteUserRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => yara.deleteUserRule(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["yara", "rules"] });
      qc.invalidateQueries({ queryKey: ["yara", "status"] });
    },
  });
}

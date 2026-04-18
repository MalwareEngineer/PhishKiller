import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  phishmatch,
  type PhishMatchEntityType,
  type PhishMatchSignals,
} from "@/lib/api";

/** Rank candidate actors/families/campaigns for a kit. */
export function usePhishMatchForKit(kitId: string | undefined) {
  return useQuery({
    queryKey: ["phishmatch", "kit", kitId],
    queryFn: () => phishmatch.scoreKit(kitId!),
    enabled: !!kitId,
    // Scoring is expensive; cache hard once we have it.
    staleTime: 60_000,
  });
}

/** Reverse lookup — unattributed kits scoring against an entity. */
export function usePhishMatchSuggestionsForEntity(
  entityType: PhishMatchEntityType | undefined,
  entityId: string | undefined,
  limit = 20,
) {
  return useQuery({
    queryKey: ["phishmatch", "entity", entityType, entityId, limit],
    queryFn: () =>
      phishmatch.suggestKits(entityType!, entityId!, limit),
    enabled: !!entityType && !!entityId,
    staleTime: 60_000,
  });
}

/** Commit an attribution decision. */
export function useAttributeKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: {
      kit_id: string;
      entity_type: PhishMatchEntityType;
      entity_id: string;
      confidence: "verified" | "suspected";
      attributed_by?: string | null;
      evidence_snapshot?: PhishMatchSignals | null;
    }) =>
      phishmatch.attribute(args.kit_id, {
        entity_type: args.entity_type,
        entity_id: args.entity_id,
        confidence: args.confidence,
        attributed_by: args.attributed_by,
        evidence_snapshot: args.evidence_snapshot,
      }),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["phishmatch", "kit", vars.kit_id] });
      qc.invalidateQueries({ queryKey: ["kit", vars.kit_id] });
      qc.invalidateQueries({ queryKey: [vars.entity_type] });
      qc.invalidateQueries({
        queryKey: [vars.entity_type === "actor" ? "actor" : vars.entity_type, vars.entity_id],
      });
      qc.invalidateQueries({
        queryKey: ["phishmatch", "entity", vars.entity_type, vars.entity_id],
      });
    },
  });
}

/** Remove an attribution link. */
export function useUnattributeKit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: {
      kit_id: string;
      entity_type: PhishMatchEntityType;
      entity_id: string;
    }) =>
      phishmatch.unattribute(args.kit_id, args.entity_type, args.entity_id),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["phishmatch", "kit", vars.kit_id] });
      qc.invalidateQueries({ queryKey: ["kit", vars.kit_id] });
      qc.invalidateQueries({ queryKey: [vars.entity_type] });
      qc.invalidateQueries({
        queryKey: ["phishmatch", "entity", vars.entity_type, vars.entity_id],
      });
    },
  });
}

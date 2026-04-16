import { useActors } from "@/hooks/use-actors";
import { useCampaigns } from "@/hooks/use-campaigns";
import { useFamilies } from "@/hooks/use-families";

interface EntityLinkSelectorsProps {
  actorId: string | undefined;
  campaignId: string | undefined;
  familyId: string | undefined;
  onActorChange: (id: string | undefined) => void;
  onCampaignChange: (id: string | undefined) => void;
  onFamilyChange: (id: string | undefined) => void;
}

export function EntityLinkSelectors({
  actorId,
  campaignId,
  familyId,
  onActorChange,
  onCampaignChange,
  onFamilyChange,
}: EntityLinkSelectorsProps) {
  const { data: actorsData } = useActors(0, 200);
  const { data: campaignsData } = useCampaigns({ offset: 0, limit: 200 });
  const { data: familiesData } = useFamilies(0, 200);

  const selectClass =
    "flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50";

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground font-medium">Link to (optional)</p>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Actor</label>
          <select
            className={selectClass}
            value={actorId ?? ""}
            onChange={(e) => onActorChange(e.target.value || undefined)}
          >
            <option value="">None</option>
            {(actorsData?.items ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Campaign</label>
          <select
            className={selectClass}
            value={campaignId ?? ""}
            onChange={(e) => onCampaignChange(e.target.value || undefined)}
          >
            <option value="">None</option>
            {(campaignsData?.items ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Family</label>
          <select
            className={selectClass}
            value={familyId ?? ""}
            onChange={(e) => onFamilyChange(e.target.value || undefined)}
          >
            <option value="">None</option>
            {(familiesData?.items ?? []).map((f) => (
              <option key={f.id} value={f.id}>{f.name}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

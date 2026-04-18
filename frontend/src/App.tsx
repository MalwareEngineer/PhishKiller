import { Routes, Route } from "react-router-dom";
import { Shell } from "@/components/layout/shell";
import { DashboardPage } from "@/pages/dashboard";
import { KitsPage } from "@/pages/kits";
import { KitDetailPage } from "@/pages/kit-detail";
import { InvestigationsPage } from "@/pages/investigations";
import { InvestigationDetailPage } from "@/pages/investigation-detail";
import { IndicatorsPage } from "@/pages/indicators";
import { ActorsPage } from "@/pages/actors";
import { ActorDetailPage } from "@/pages/actor-detail";
import { CampaignsPage } from "@/pages/campaigns";
import { CampaignDetailPage } from "@/pages/campaign-detail";
import { FamiliesPage } from "@/pages/families";
import { FamilyDetailPage } from "@/pages/family-detail";
import { PhishDiffPage } from "@/pages/phish-diff";
import { PhishMatchPage } from "@/pages/phish-match";

export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<DashboardPage />} />
        <Route path="kits" element={<KitsPage />} />
        <Route path="kits/:id" element={<KitDetailPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="investigations/:id" element={<InvestigationDetailPage />} />
        <Route path="indicators" element={<IndicatorsPage />} />
        <Route path="actors" element={<ActorsPage />} />
        <Route path="actors/:id" element={<ActorDetailPage />} />
        <Route path="campaigns" element={<CampaignsPage />} />
        <Route path="campaigns/:id" element={<CampaignDetailPage />} />
        <Route path="families" element={<FamiliesPage />} />
        <Route path="families/:id" element={<FamilyDetailPage />} />
        <Route path="phish-diff" element={<PhishDiffPage />} />
        <Route path="phish-match/:kitId" element={<PhishMatchPage />} />
      </Route>
    </Routes>
  );
}

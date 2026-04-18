import type {
  PaginatedResponse,
  KitSummary,
  KitDetail,
  KitDeletePreview,
  KitContentResponse,
  KitSubmitResponse,
  KitBulkResponse,
  KitBulkUploadResponse,
  SimilarKit,
  ScreenshotsResponse,
  NetworkLogResponse,
  BrowserResourcesResponse,
  DeobfuscationPreviewResponse,
  InvestigationSummary,
  InvestigationDetail,
  InvestigationTreeNode,
  InvestigationSubmitResponse,
  IndicatorSummary,
  IndicatorDetail,
  IndicatorStats,
  ActorSummary,
  ActorDetail,
  CampaignSummary,
  CampaignDetail,
  FamilySummary,
  FamilyDetail,
  HealthResponse,
  AnalysisResultDetail,
  TaskStatusResponse,
  DiffPairGroupsResponse,
  DiffablePair,
  DiffCompareResponse,
} from "@/types/api";

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Kits ──

export const kits = {
  list: (params?: { offset?: number; limit?: number; status_filter?: string; source_feed?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.status_filter) q.set("status_filter", params.status_filter);
    if (params?.source_feed) q.set("source_feed", params.source_feed);
    return request<PaginatedResponse<KitSummary>>(`/kits?${q}`);
  },
  get: (id: string) => request<KitDetail>(`/kits/${id}`),
  submit: (url: string, source_feed?: string, force?: boolean, entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) =>
    request<KitSubmitResponse>("/kits", {
      method: "POST",
      body: JSON.stringify({ url, source_feed, force, ...entityIds }),
    }),
  upload: async (file: File, source_feed?: string, entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) => {
    const form = new FormData();
    form.append("file", file);
    if (source_feed) form.append("source_feed", source_feed);
    if (entityIds?.actor_id) form.append("actor_id", entityIds.actor_id);
    if (entityIds?.campaign_id) form.append("campaign_id", entityIds.campaign_id);
    if (entityIds?.family_id) form.append("family_id", entityIds.family_id);
    const res = await fetch(`${BASE}/kits/upload`, { method: "POST", body: form });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    return res.json() as Promise<KitSubmitResponse>;
  },
  actors: (id: string) =>
    request<{ id: string; name: string }[]>(`/kits/${id}/actors`),
  similar: (id: string, threshold?: number) => {
    const q = threshold ? `?threshold=${threshold}` : "";
    return request<SimilarKit[]>(`/kits/${id}/similar${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(`/kits/${id}/indicators?offset=${offset}&limit=${limit}`),
  reanalyze: (id: string) =>
    request<{ kit_id: string; task_id: string }>(`/kits/${id}/reanalyze`, { method: "POST" }),
  bulkSubmit: (urls: string[], entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) =>
    request<KitBulkResponse>("/kits/bulk", {
      method: "POST",
      body: JSON.stringify({ urls, ...entityIds }),
    }),
  bulkUpload: async (files: File[], entityIds?: { actor_id?: string; campaign_id?: string; family_id?: string }) => {
    const form = new FormData();
    for (const file of files) form.append("files", file);
    if (entityIds?.actor_id) form.append("actor_id", entityIds.actor_id);
    if (entityIds?.campaign_id) form.append("campaign_id", entityIds.campaign_id);
    if (entityIds?.family_id) form.append("family_id", entityIds.family_id);
    const res = await fetch(`${BASE}/kits/upload/bulk`, { method: "POST", body: form });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    return res.json() as Promise<KitBulkUploadResponse>;
  },
  delete: (id: string) => request<void>(`/kits/${id}`, { method: "DELETE" }),
  deletePreview: (id: string) => request<KitDeletePreview>(`/kits/${id}/delete-preview`),
  content: (id: string) => request<KitContentResponse>(`/kits/${id}/content`),
  screenshots: (id: string) => request<ScreenshotsResponse>(`/kits/${id}/screenshots`),
  networkLog: (id: string) => request<NetworkLogResponse>(`/kits/${id}/network-log`),
  browserResources: (id: string) => request<BrowserResourcesResponse>(`/kits/${id}/browser-resources`),
  deobfuscationPreview: (id: string) => request<DeobfuscationPreviewResponse>(`/kits/${id}/deobfuscation-preview`),
  addToCampaign: (kitId: string, campaignId: string) =>
    request<{ added: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-campaign`,
      { method: "POST", body: JSON.stringify({ campaign_id: campaignId }) },
    ),
  addToActor: (kitId: string, actorId: string) =>
    request<{ linked: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-actor`,
      { method: "POST", body: JSON.stringify({ actor_id: actorId }) },
    ),
  addToFamily: (kitId: string, familyId: string) =>
    request<{ added: number; kit_id: string; used_root: boolean; message: string }>(
      `/kits/${kitId}/add-to-family`,
      { method: "POST", body: JSON.stringify({ family_id: familyId }) },
    ),
  bulkDelete: (ids: string[]) =>
    request<{ deleted: number }>("/kits/bulk-delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
  search: (params: { q?: string; yara_rule?: string; tlsh?: string; tlsh_threshold?: number; offset?: number; limit?: number }) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.yara_rule) q.set("yara_rule", params.yara_rule);
    if (params.tlsh) q.set("tlsh", params.tlsh);
    if (params.tlsh_threshold) q.set("tlsh_threshold", String(params.tlsh_threshold));
    if (params.offset) q.set("offset", String(params.offset));
    if (params.limit) q.set("limit", String(params.limit));
    return request<PaginatedResponse<KitSummary>>(`/kits/search?${q}`);
  },
};

// ── Investigations ──

export const investigations = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<InvestigationSummary>>(`/investigations?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<InvestigationDetail>(`/investigations/${id}`),
  tree: (id: string) => request<InvestigationTreeNode[]>(`/investigations/${id}/tree`),
  kits: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<KitSummary>>(`/investigations/${id}/kits?offset=${offset}&limit=${limit}`),
  create: (data: {
    name: string;
    url: string;
    max_depth?: number;
    actor_id?: string;
    campaign_id?: string;
    family_id?: string;
  }) =>
    request<InvestigationSubmitResponse>("/investigations", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  createFromFile: async (formData: FormData) => {
    const res = await fetch(`${BASE}/investigations/upload`, {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<InvestigationSubmitResponse>;
  },
  update: (id: string, data: Partial<InvestigationDetail>) =>
    request<InvestigationDetail>(`/investigations/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  delete: (id: string) => request<void>(`/investigations/${id}`, { method: "DELETE" }),
  bulkDelete: (ids: string[]) =>
    request<{ deleted: number }>("/investigations/bulk-delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    }),
};

// ── Indicators ──

export const indicators = {
  list: (params?: { offset?: number; limit?: number; type_filter?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.type_filter) q.set("type_filter", params.type_filter);
    return request<PaginatedResponse<IndicatorSummary>>(`/indicators?${q}`);
  },
  search: (query: string, params?: { offset?: number; limit?: number; type_filter?: string }) => {
    const q = new URLSearchParams({ q: query });
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.type_filter) q.set("type_filter", params.type_filter);
    return request<PaginatedResponse<IndicatorSummary>>(`/indicators/search?${q}`);
  },
  stats: () => request<IndicatorStats[]>("/indicators/stats"),
  get: (id: string) => request<IndicatorDetail>(`/indicators/${id}`),
};

// ── Actors ──

export const actors = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<ActorSummary>>(`/actors?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<ActorDetail>(`/actors/${id}`),
  create: (data: { name: string; aliases?: string[]; description?: string; email_addresses?: string[]; telegram_handles?: string[] }) =>
    request<ActorDetail>("/actors", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<ActorDetail>) =>
    request<ActorDetail>(`/actors/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/actors/${id}`, { method: "DELETE" }),
  link: (id: string, indicator_ids: string[]) =>
    request<{ linked: number }>(`/actors/${id}/link`, {
      method: "POST",
      body: JSON.stringify({ indicator_ids }),
    }),
};

// ── Campaigns ──

export const campaigns = {
  list: (params?: { offset?: number; limit?: number; target_brand?: string }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.target_brand) q.set("target_brand", params.target_brand);
    return request<PaginatedResponse<CampaignSummary>>(`/campaigns?${q}`);
  },
  get: (id: string) => request<CampaignDetail>(`/campaigns/${id}`),
  create: (data: { name: string; description?: string; target_brand?: string }) =>
    request<CampaignDetail>("/campaigns", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<CampaignDetail>) =>
    request<CampaignDetail>(`/campaigns/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/campaigns/${id}`, { method: "DELETE" }),
  addKits: (id: string, kit_ids: string[]) =>
    request<{ added: number }>(`/campaigns/${id}/kits`, {
      method: "POST",
      body: JSON.stringify({ kit_ids }),
    }),
};

// ── Families ──

export const families = {
  list: (offset = 0, limit = 50) =>
    request<PaginatedResponse<FamilySummary>>(`/families?offset=${offset}&limit=${limit}`),
  get: (id: string) => request<FamilyDetail>(`/families/${id}`),
  create: (data: { name: string; aliases?: string[]; description?: string }) =>
    request<FamilyDetail>("/families", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<FamilyDetail>) =>
    request<FamilyDetail>(`/families/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  delete: (id: string) =>
    request<void>(`/families/${id}`, { method: "DELETE" }),
  addKits: (id: string, kit_ids: string[]) =>
    request<{ added: number }>(`/families/${id}/kits`, {
      method: "POST",
      body: JSON.stringify({ kit_ids }),
    }),
  addActors: (id: string, actor_ids: string[]) =>
    request<{ added: number }>(`/families/${id}/actors`, {
      method: "POST",
      body: JSON.stringify({ actor_ids }),
    }),
};

// ── Analysis ──

export const analysis = {
  result: (id: string) => request<AnalysisResultDetail>(`/analysis/results/${id}`),
  taskStatus: (taskId: string) => request<TaskStatusResponse>(`/analysis/tasks/${taskId}`),
};

// ── PhishDiff ──

export const diff = {
  pairGroups: (params?: { offset?: number; limit?: number; max_distance?: number; max_size_ratio?: number }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.max_distance) q.set("max_distance", String(params.max_distance));
    if (params?.max_size_ratio) q.set("max_size_ratio", String(params.max_size_ratio));
    return request<DiffPairGroupsResponse>(`/diff/pairs?${q}`);
  },
  pairs: (kitId: string, params?: { max_distance?: number; max_size_ratio?: number }) => {
    const q = new URLSearchParams();
    if (params?.max_distance) q.set("max_distance", String(params.max_distance));
    if (params?.max_size_ratio) q.set("max_size_ratio", String(params.max_size_ratio));
    return request<DiffablePair[]>(`/diff/pairs/${kitId}?${q}`);
  },
  compare: (kit_a_id: string, kit_b_id: string, normalize = false) =>
    request<DiffCompareResponse>("/diff/compare", {
      method: "POST",
      body: JSON.stringify({ kit_a_id, kit_b_id, normalize }),
    }),
};

// ── PhishMatch ──

export type PhishMatchEntityType = "actor" | "family" | "campaign";

export interface PhishMatchSignals {
  total: number;
  tlsh: number;
  ioc: number;
  yara: number;
  source_url: number;
  redirect_chain: number;
  evidence: {
    tlsh: Array<{ kit_id: string; distance: number; tlsh: string }>;
    ioc: Array<{
      type: string;
      value: string;
      weight: number;
      subject_indicator_id: string;
      peer_indicator_id: string;
      peer_kit_id: string;
    }>;
    yara: string[];
    source_url: string[];
    redirect: string[];
  };
}

export interface PhishMatchCandidate {
  entity_type: PhishMatchEntityType;
  entity_id: string;
  entity_name: string;
  auto_generated: boolean;
  score: number;
  signals: PhishMatchSignals;
  supporting_kit_ids: string[];
}

export interface PhishMatchResult {
  kit_id: string;
  actors: PhishMatchCandidate[];
  families: PhishMatchCandidate[];
  campaigns: PhishMatchCandidate[];
  no_matches_reason: string | null;
  min_surface_score: number;
}

export interface PhishMatchSuggestion {
  kit_id: string;
  source_url: string;
  sha256: string | null;
  score: number;
  via_kit_id: string | null;
  signals: PhishMatchSignals;
}

export interface PhishMatchSuggestionsResponse {
  entity_type: PhishMatchEntityType;
  entity_id: string;
  suggestions: PhishMatchSuggestion[];
}

export const phishmatch = {
  /** Rank candidate entities for a kit. */
  scoreKit: (kitId: string) =>
    request<PhishMatchResult>(`/phishmatch/kit/${kitId}`),

  /** Reverse lookup — unattributed kits that score high against an entity. */
  suggestKits: (
    entityType: PhishMatchEntityType,
    entityId: string,
    limit = 20,
  ) =>
    request<PhishMatchSuggestionsResponse>(
      `/phishmatch/entity/${entityType}/${entityId}?limit=${limit}`,
    ),

  /** Commit an attribution (kit → entity link) with evidence. */
  attribute: (kitId: string, payload: {
    entity_type: PhishMatchEntityType;
    entity_id: string;
    confidence: "verified" | "suspected";
    attributed_by?: string | null;
    evidence_snapshot?: PhishMatchSignals | null;
  }) =>
    request<{
      kit_id: string;
      entity_type: PhishMatchEntityType;
      entity_id: string;
      created: boolean;
      confidence: string;
      attributed_at: string;
    }>(`/phishmatch/kit/${kitId}/attribute`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** Remove a kit → entity link. */
  unattribute: (
    kitId: string,
    entityType: PhishMatchEntityType,
    entityId: string,
  ) =>
    request<void>(
      `/phishmatch/kit/${kitId}/attribute?entity_type=${entityType}&entity_id=${entityId}`,
      { method: "DELETE" },
    ),
};

// ── Health ──

export const health = {
  check: () => request<HealthResponse>("/health"),
};

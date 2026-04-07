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
  HealthResponse,
  AnalysisResultDetail,
  TaskStatusResponse,
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
  submit: (url: string, source_feed?: string, force?: boolean) =>
    request<KitSubmitResponse>("/kits", {
      method: "POST",
      body: JSON.stringify({ url, source_feed, force }),
    }),
  upload: async (file: File, source_feed?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (source_feed) form.append("source_feed", source_feed);
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
  bulkSubmit: (urls: string[]) =>
    request<KitBulkResponse>("/kits/bulk", {
      method: "POST",
      body: JSON.stringify({ urls }),
    }),
  bulkUpload: async (files: File[]) => {
    const form = new FormData();
    for (const file of files) form.append("files", file);
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
  create: (url: string, max_depth = 3) =>
    request<InvestigationSubmitResponse>("/investigations", {
      method: "POST",
      body: JSON.stringify({ url, max_depth }),
    }),
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

// ── Analysis ──

export const analysis = {
  result: (id: string) => request<AnalysisResultDetail>(`/analysis/results/${id}`),
  taskStatus: (taskId: string) => request<TaskStatusResponse>(`/analysis/tasks/${taskId}`),
};

// ── Health ──

export const health = {
  check: () => request<HealthResponse>("/health"),
};

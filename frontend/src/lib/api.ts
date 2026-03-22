import type {
  PaginatedResponse,
  KitSummary,
  KitDetail,
  KitSubmitResponse,
  SimilarKit,
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
  FeedEntrySummary,
  FeedStats,
  FeedIngestResponse,
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
  submit: (url: string, source_feed?: string) =>
    request<KitSubmitResponse>("/kits", {
      method: "POST",
      body: JSON.stringify({ url, source_feed }),
    }),
  upload: async (file: File, source_feed?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (source_feed) form.append("source_feed", source_feed);
    const res = await fetch(`${BASE}/kits/upload`, { method: "POST", body: form });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    return res.json() as Promise<KitSubmitResponse>;
  },
  similar: (id: string, threshold?: number) => {
    const q = threshold ? `?threshold=${threshold}` : "";
    return request<SimilarKit[]>(`/kits/${id}/similar${q}`);
  },
  indicators: (id: string, offset = 0, limit = 50) =>
    request<PaginatedResponse<IndicatorSummary>>(`/kits/${id}/indicators?offset=${offset}&limit=${limit}`),
  reanalyze: (id: string) =>
    request<{ kit_id: string; task_id: string }>(`/kits/${id}/reanalyze`, { method: "POST" }),
  delete: (id: string) => request<void>(`/kits/${id}`, { method: "DELETE" }),
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
  addKits: (id: string, kit_ids: string[]) =>
    request<{ added: number }>(`/campaigns/${id}/kits`, {
      method: "POST",
      body: JSON.stringify({ kit_ids }),
    }),
};

// ── Feeds ──

export const feeds = {
  entries: (params?: { offset?: number; limit?: number; source?: string; processed?: boolean }) => {
    const q = new URLSearchParams();
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.source) q.set("source", params.source);
    if (params?.processed !== undefined) q.set("processed", String(params.processed));
    return request<PaginatedResponse<FeedEntrySummary>>(`/feeds/entries?${q}`);
  },
  stats: () => request<FeedStats[]>("/feeds/stats"),
  ingest: (source = "all") =>
    request<FeedIngestResponse>("/feeds/ingest", {
      method: "POST",
      body: JSON.stringify({ source }),
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

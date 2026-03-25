// ── Enums ──

export type KitStatus =
  | "pending"
  | "downloading"
  | "downloaded"
  | "analyzing"
  | "analyzed"
  | "failed";

export type IndicatorType =
  | "email"
  | "telegram_bot_token"
  | "telegram_chat_id"
  | "c2_url"
  | "ip_address"
  | "smtp_credential"
  | "base64_block"
  | "domain"
  | "phone_number"
  | "cryptocurrency_wallet"
  | "source_url";

export type AnalysisType =
  | "hash"
  | "ioc_extraction"
  | "deobfuscation"
  | "yara_scan"
  | "similarity"
  | "eml_parse"
  | "qr_decode"
  | "link_score"
  | "redirect_chain";

// ── Paginated response ──

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
}

// ── Kits ──

export interface KitSummary {
  id: string;
  source_url: string;
  sha256?: string;
  tlsh?: string;
  status: KitStatus;
  file_size?: number;
  source_feed?: string;
  created_at: string;
}

export interface KitDetail extends KitSummary {
  md5?: string;
  sha1?: string;
  filename?: string;
  mime_type?: string;
  error_message?: string;
  parent_kit_id?: string;
  investigation_id?: string;
  chain_depth: number;
  discovery_method?: string;
  indicators: IndicatorBrief[];
  analysis_results: AnalysisResultBrief[];
  campaigns: CampaignBrief[];
  child_kits: KitSummary[];
}

export interface KitSubmitResponse {
  kit_id: string;
  task_id: string;
  duplicate: boolean;
  message: string;
}

export interface KitBulkResponse {
  submitted: number;
  skipped_duplicate: number;
  results: { url: string; kit_id: string; task_id?: string; duplicate: boolean }[];
}

export interface KitBulkUploadResult {
  filename: string;
  kit_id: string;
  task_id?: string;
  investigation_id?: string;
}

export interface KitBulkUploadResponse {
  submitted: number;
  results: KitBulkUploadResult[];
}

export interface SimilarKit {
  id: string;
  sha256?: string;
  tlsh?: string;
  source_url: string;
  distance: number;
}

export interface KitDeletePreview {
  kit_id: string;
  total_kits: number;
  child_kits: number;
  indicators: number;
  analysis_results: number;
  campaign_links: number;
  investigations: number;
}

// ── Investigations ──

export interface InvestigationSummary {
  id: string;
  name?: string;
  description?: string;
  status: string;
  max_depth: number;
  total_kits: number;
  total_depth_reached: number;
  created_at: string;
}

export interface InvestigationDetail extends InvestigationSummary {
  root_kit?: KitSummary;
}

export interface InvestigationTreeNode {
  kit: KitSummary;
  discovery_method?: string;
  chain_depth: number;
  children: InvestigationTreeNode[];
}

export interface InvestigationSubmitResponse {
  investigation_id: string;
  kit_id: string;
  task_id: string;
  message: string;
}

// ── Indicators ──

export interface IndicatorSummary {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
  source_file?: string;
  kit_id: string;
  created_at: string;
}

export interface IndicatorDetail extends IndicatorSummary {
  context?: string;
  actor_id?: string;
}

export interface IndicatorBrief {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
}

export interface IndicatorStats {
  type: string;
  count: number;
}

// ── Actors ──

export interface ActorSummary {
  id: string;
  name: string;
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
  created_at: string;
}

export interface ActorDetail extends ActorSummary {
  description?: string;
  email_addresses?: string[];
  telegram_handles?: string[];
}

export interface ActorBrief {
  id: string;
  name: string;
}

// ── Campaigns ──

export interface CampaignSummary {
  id: string;
  name: string;
  target_brand?: string;
  start_date?: string;
  end_date?: string;
  created_at: string;
}

export interface CampaignDetail extends CampaignSummary {
  description?: string;
  auto_generated?: boolean;
  kits: KitSummary[];
  actors: ActorBrief[];
}

export interface CampaignBrief {
  id: string;
  name: string;
  target_brand?: string;
}

// ── Analysis ──

export interface AnalysisResultBrief {
  id: string;
  analysis_type: AnalysisType;
  result_data?: Record<string, unknown>;
  duration_seconds?: number;
  files_processed?: number;
  error?: string;
  created_at: string;
}

export interface AnalysisResultDetail extends AnalysisResultBrief {
  kit_id: string;
  result_data: Record<string, unknown>;
  error?: string;
}

// ── Kit Content ──

export interface KitContentFile {
  filename: string;
  content: string;
  size: number;
  mime_type?: string;
  truncated: boolean;
}

export interface KitContentResponse {
  kit_id: string;
  files: KitContentFile[];
}

// ── Health ──

export interface HealthResponse {
  status: "ok" | "degraded";
  services: Record<string, { status: "ok" | "error"; detail?: string }>;
}

// ── Task polling ──

export interface TaskStatusResponse {
  task_id: string;
  status: string;
  result?: Record<string, unknown>;
}

export type Membership = {
  tenant_id: number;
  tenant_name: string;
  role: string;
  is_personal: boolean;
};

export type AuthResponse = {
  access_token: string;
  token_type: string;
  tenant_id: number;
  role: string;
  memberships: Membership[];
};

export type OnboardingStatusResponse = {
  ok: boolean;
  needs_onboarding: boolean;
};

export type OnboardingBootstrapResponse = {
  ok: boolean;
  tenant_id: number;
  tenant_name: string;
  admin_external_user: string;
  provider: {
    provider: string;
    model: string;
    base_url?: string | null;
    source?: string;
    has_api_key?: boolean;
    api_key_tail?: string | null;
    [key: string]: unknown;
  };
};

export type MeResponse = {
  user_id: number;
  email: string;
  tenant_id: number;
  role: string;
  is_personal: boolean;
  memberships: Membership[];
};

export type ChatRequest = {
  prompt: string;
  purpose?: string;
  rehydrate_response?: boolean;
};

export type ChatResponse = {
  request_id: string;
  provider: string;
  model: string;
  cleaned_prompt: string;
  detections: Array<Record<string, unknown>>;
  entity_counts: Record<string, number>;
  risk_categories: Record<string, number>;
  risk_score: number;
  risk_level: string;
  redactions_applied: number;
  severity: string;
  decision: string;
  decision_reasons: string[];
  show_sanitized_prompt_admin: boolean;
  assistant_response: string;
  redaction_metadata: Record<string, unknown>;
  ai_response_clean: string;
  ai_response_rehydrated?: string | null;
};

export type FileScanResponse = {
  request_id: string;
  filename: string;
  content_type: string;
  file_type: string;
  size_bytes: number;
  extracted_text: string;
  redacted_text: string;
  entities: Array<Record<string, unknown>>;
  entity_counts: Record<string, number>;
  risk_categories: Record<string, number>;
  findings_count: number;
  risk_score: number;
  risk_level: string;
  severity: string;
  decision: string;
  blocked: boolean;
  allowed: boolean;
  decision_reasons: string[];
  injection_detected: boolean;
};

export type ActivityItem = {
  id: string;
  ts: string;
  user: string;
  purpose?: string | null;
  provider?: string | null;
  model?: string | null;
  decision: string;
  risk_level?: string | null;
  severity?: string | null;
  risk_score: number;
  detections_count: number;
  injection_detected: boolean;
  entity_counts: Record<string, number>;
  risk_categories: Record<string, number>;
};

export type ActivityResponse = {
  tenant_id: number;
  count: number;
  items: ActivityItem[];
};

export type AnalyticsResponse = {
  tenant_id: number;
  summary: {
    total_requests: number;
    avg_risk_score: number;
    high_or_critical: number;
  };
  usage: {
    tenant_id: number;
    daily_requests_limit: number;
    rpm_limit: number;
    today_request_count: number;
    today_token_count: number;
    daily_requests_remaining: number;
    daily_percent_used: number;
  };
  risk_trend: Array<{
    date: string;
    avg_risk: number;
    count: number;
  }>;
  entity_totals: Record<string, number>;
  compliance: {
    total_requests: number;
    allowed: number;
    redacted: number;
    blocked: number;
    injection_attempts: number;
    risk_distribution: Record<string, number>;
    provider_usage: Record<string, number>;
    model_usage: Record<string, number>;
    top_users: Array<{ user: string; count: number }>;
    redactions_by_category: Record<string, number>;
  };
};

export type TenantPolicy = {
  tenant_id: number;
  pii_action: "allow" | "redact" | "block";
  financial_action: "allow" | "redact" | "block";
  secrets_action: "allow" | "redact" | "block";
  health_action: "allow" | "redact" | "block";
  ip_action: "allow" | "redact" | "block";
  block_threshold: "high" | "critical";
  store_original_prompt: boolean;
  show_sanitized_prompt_admin: boolean;
  created_at: string;
  updated_at: string;
};

export type TenantProviderConfig = {
  tenant_id: number;
  provider: string;
  model: string;
  base_url: string | null;
  source: string;
  has_api_key: boolean;
  api_key_tail: string | null;
};

export type TenantKeyItem = {
  provider: string;
  has_key: boolean;
  api_key_tail: string | null;
  updated_at: string | null;
};

export type TenantKeysResponse = {
  tenant_id: number;
  items: TenantKeyItem[];
};

export type InviteToken = {
  tenant_id: number;
  token: string;
  email: string | null;
  role: string;
  expires_at: string;
  max_uses: number | null;
  uses_count: number;
};

export type UsageSummary = {
  tenant_id: number;
  daily_requests_limit: number;
  rpm_limit: number;
  today_request_count: number;
  today_token_count: number;
  daily_requests_remaining: number;
  daily_percent_used: number;
};

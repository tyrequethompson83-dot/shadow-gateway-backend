import type {
  ActivityResponse,
  AnalyticsResponse,
  AuthResponse,
  ChatRequest,
  ChatResponse,
  FileScanResponse,
  InviteToken,
  MeResponse,
  OnboardingBootstrapResponse,
  OnboardingStatusResponse,
  TenantKeysResponse,
  TenantPolicy,
  TenantProviderConfig,
  UsageSummary,
} from "@/types/api";

const DEFAULT_API_BASE_URL = "https://app.shadowaigateway.com";
const RAW_API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || DEFAULT_API_BASE_URL;
const API_BASE_URL = `${RAW_API_BASE_URL}`.replace(/\/$/, "");

if (!API_BASE_URL || API_BASE_URL === "undefined") {
  throw new Error("NEXT_PUBLIC_API_BASE_URL is not set.");
}

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `Request failed with ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

type RequestOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  token?: string;
  body?: unknown;
};

function buildHeaders(token?: string, body?: unknown): HeadersInit {
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (body !== undefined && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

async function parseResponse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) {
    return null;
  }

  const contentType = res.headers.get("content-type") ?? "";
  const trimmed = text.trim();
  if (contentType.includes("application/json") || trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // Fall through to the raw text body if the upstream response lied about content type.
    }
  }

  return trimmed;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const res = await fetch(url, {
    method: options.method ?? "GET",
    headers: buildHeaders(options.token, options.body),
    body:
      options.body === undefined
        ? undefined
        : options.body instanceof FormData
        ? options.body
        : JSON.stringify(options.body),
    cache: "no-store",
  });

  const payload = await parseResponse(res);
  if (!res.ok) {
    const detail =
      payload && typeof payload === "object" && payload !== null && "detail" in payload
        ? (payload as { detail: unknown }).detail
        : payload;
    throw new ApiError(res.status, detail);
  }
  return payload as T;
}

export function getApiBaseUrl(): string {
  return API_BASE_URL;
}

export async function login(input: {
  email: string;
  password: string;
  tenant_id?: number;
}): Promise<AuthResponse> {
  return request<AuthResponse>("/auth/login", {
    method: "POST",
    body: input,
  });
}

export async function signupCompany(input: {
  company_name: string;
  admin_email: string;
  password: string;
}): Promise<AuthResponse> {
  return request<AuthResponse>("/auth/signup/company", {
    method: "POST",
    body: input,
  });
}

export async function signupIndividual(input: {
  name_or_label?: string;
  email: string;
  password: string;
}): Promise<AuthResponse> {
  return request<AuthResponse>("/auth/signup/individual", {
    method: "POST",
    body: input,
  });
}

export async function signupInvite(input: {
  token: string;
  email: string;
  password: string;
}): Promise<AuthResponse> {
  return request<AuthResponse>("/auth/signup/invite", {
    method: "POST",
    body: input,
  });
}

export async function logout(token: string): Promise<void> {
  await request<{ ok: boolean }>("/auth/logout", {
    method: "POST",
    token,
  });
}

export async function getMe(token: string): Promise<MeResponse> {
  return request<MeResponse>("/me", { token });
}

export async function deleteMe(token: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>("/me", { method: "DELETE", token });
}

export async function getOnboardingStatus(): Promise<OnboardingStatusResponse> {
  return request<OnboardingStatusResponse>("/onboarding/status");
}

export async function bootstrapOnboarding(input: {
  tenant_name: string;
  admin_external_user: string;
  admin_password?: string;
  provider: string;
  model?: string;
  api_key?: string;
  base_url?: string;
}): Promise<OnboardingBootstrapResponse> {
  return request<OnboardingBootstrapResponse>("/onboarding/bootstrap", {
    method: "POST",
    body: input,
  });
}

export async function sendChat(token: string, payload: ChatRequest): Promise<ChatResponse> {
  return request<ChatResponse>("/chat", {
    method: "POST",
    token,
    body: payload,
  });
}

export async function scanFile(token: string, file: File, purpose = "next_chat_attachment"): Promise<FileScanResponse> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("purpose", purpose);
  return request<FileScanResponse>("/files/scan", {
    method: "POST",
    token,
    body: formData,
  });
}

export async function getActivity(token: string, limit = 100): Promise<ActivityResponse> {
  return request<ActivityResponse>(`/tenant/activity?limit=${limit}`, { token });
}

export async function getAnalytics(token: string, days = 14): Promise<AnalyticsResponse> {
  return request<AnalyticsResponse>(`/tenant/analytics?days=${days}`, { token });
}

export async function getTenantProvider(token: string): Promise<TenantProviderConfig> {
  return request<TenantProviderConfig>("/tenant/provider", { token });
}

export async function getTenantKeys(token: string): Promise<TenantKeysResponse> {
  return request<TenantKeysResponse>("/tenant/keys", { token });
}

export async function upsertTenantKey(
  token: string,
  payload: { provider: string; api_key: string; model?: string; base_url?: string },
): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>("/tenant/keys", {
    method: "PUT",
    token,
    body: payload,
  });
}

export async function deleteTenantKey(token: string, provider: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/tenant/keys/${provider}`, {
    method: "DELETE",
    token,
  });
}

export async function createInvite(
  token: string,
  payload: { email?: string | null; role: string; expires_hours: number; max_uses?: number | null },
): Promise<{ ok: boolean } & InviteToken> {
  return request<{ ok: boolean } & InviteToken>("/tenant/admin/invite", {
    method: "POST",
    token,
    body: payload,
  });
}

export async function getTenantPolicy(token: string): Promise<TenantPolicy> {
  return request<TenantPolicy>("/tenant/admin/policy", { token });
}

export async function updateTenantPolicy(
  token: string,
  payload: Partial<Pick<
    TenantPolicy,
    | "pii_action"
    | "financial_action"
    | "secrets_action"
    | "health_action"
    | "ip_action"
    | "block_threshold"
    | "store_original_prompt"
    | "show_sanitized_prompt_admin"
  >>,
): Promise<TenantPolicy> {
  return request<TenantPolicy>("/tenant/admin/policy", {
    method: "PUT",
    token,
    body: payload,
  });
}

export async function getUsageSummary(token: string): Promise<UsageSummary> {
  return request<UsageSummary>("/tenant/admin/usage-summary", { token });
}

"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { RefreshCcw, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import {
  deleteMe,
  deleteTenantKey,
  getTenantKeys,
  getTenantPolicy,
  getTenantProvider,
  getUsageSummary,
  createInvite,
  upsertTenantKey,
  updateTenantPolicy,
} from "@/lib/api";
import type { InviteToken, TenantKeyItem, TenantPolicy, TenantProviderConfig, UsageSummary } from "@/types/api";

const PROVIDERS = ["gemini", "openai", "groq", "anthropic"];

type PolicyDraft = Pick<
  TenantPolicy,
  | "pii_action"
  | "financial_action"
  | "secrets_action"
  | "health_action"
  | "ip_action"
  | "block_threshold"
  | "store_original_prompt"
  | "show_sanitized_prompt_admin"
>;

function emptyPolicy(): PolicyDraft {
  return {
    pii_action: "redact",
    financial_action: "redact",
    secrets_action: "block",
    health_action: "redact",
    ip_action: "redact",
    block_threshold: "critical",
    store_original_prompt: true,
    show_sanitized_prompt_admin: true,
  };
}

function toMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return "Request failed";
}

export default function SettingsPage() {
  const router = useRouter();
  const { token, user, refreshUser, logout } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [provider, setProvider] = useState<TenantProviderConfig | null>(null);
  const [keys, setKeys] = useState<TenantKeyItem[]>([]);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [policy, setPolicy] = useState<PolicyDraft>(emptyPolicy());

  const [providerName, setProviderName] = useState("gemini");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [savingKey, setSavingKey] = useState(false);
  const [tavilyApiKey, setTavilyApiKey] = useState("");
  const [savingTavilyKey, setSavingTavilyKey] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("employee");
  const [inviteType, setInviteType] = useState<"single" | "multi">("single");
  const [inviteHours, setInviteHours] = useState(72);
  const [inviteMaxUses, setInviteMaxUses] = useState(5);
  const [savingInvite, setSavingInvite] = useState(false);
  const [inviteResult, setInviteResult] = useState<InviteToken | null>(null);
  const [inviteLink, setInviteLink] = useState("");
  const [deletingAccount, setDeletingAccount] = useState(false);

  const isTenantAdmin = user?.role === "tenant_admin";
  const isPersonal = Boolean(user?.is_personal);

  const canEditPolicy = isTenantAdmin && !isPersonal;

  const activeMembership = useMemo(() => {
    if (!user) {
      return null;
    }
    return user.memberships.find((m) => Number(m.tenant_id) === Number(user.tenant_id)) ?? null;
  }, [user]);

  const load = async () => {
    if (!token || !user) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      await refreshUser();

      if (!isTenantAdmin) {
        setLoading(false);
        return;
      }

      const [providerPayload, keysPayload] = await Promise.all([getTenantProvider(token), getTenantKeys(token)]);
      setProvider(providerPayload);
      setKeys(keysPayload.items || []);
      setProviderName(providerPayload.provider && providerPayload.provider !== "none" ? providerPayload.provider : "gemini");
      setModel(providerPayload.model || "");
      setBaseUrl(providerPayload.base_url || "");

      if (canEditPolicy) {
        try {
          const [policyPayload, usagePayload] = await Promise.all([getTenantPolicy(token), getUsageSummary(token)]);
          setPolicy({
            pii_action: policyPayload.pii_action,
            financial_action: policyPayload.financial_action,
            secrets_action: policyPayload.secrets_action,
            health_action: policyPayload.health_action,
            ip_action: policyPayload.ip_action,
            block_threshold: policyPayload.block_threshold,
            store_original_prompt: policyPayload.store_original_prompt,
            show_sanitized_prompt_admin: policyPayload.show_sanitized_prompt_admin,
          });
          setUsage(usagePayload);
        } catch {
          // can fail for role/workspace policy gates
        }
      }
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, user?.role, user?.tenant_id]);

  const saveProviderKey = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!token) {
      return;
    }
    setSavingKey(true);
    setError("");
    try {
      await upsertTenantKey(token, {
        provider: providerName,
        api_key: apiKey,
        model: model || undefined,
        base_url: baseUrl || undefined,
      });
      setApiKey("");
      await load();
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setSavingKey(false);
    }
  };

  const saveTavilyKey = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!token) {
      return;
    }
    setSavingTavilyKey(true);
    setError("");
    try {
      await upsertTenantKey(token, {
        provider: "tavily",
        api_key: tavilyApiKey,
      });
      setTavilyApiKey("");
      await load();
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setSavingTavilyKey(false);
    }
  };

  const removeKey = async (providerToDelete: string) => {
    if (!token) {
      return;
    }
    try {
      await deleteTenantKey(token, providerToDelete);
      await load();
    } catch (err) {
      setError(toMessage(err));
    }
  };

  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!token || !canEditPolicy) {
      return;
    }
    setSavingPolicy(true);
    setError("");
    try {
      await updateTenantPolicy(token, policy);
      await load();
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setSavingPolicy(false);
    }
  };

  const saveInvite = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!token || !isTenantAdmin || isPersonal) {
      return;
    }
    setSavingInvite(true);
    setError("");
    setInviteResult(null);
    setInviteLink("");
    try {
      const payload = {
        email: inviteEmail.trim() || null,
        role: inviteRole,
        expires_hours: inviteHours,
        max_uses: inviteType === "multi" ? inviteMaxUses : null,
      };
      const created = await createInvite(token, payload);
      setInviteResult(created);
      const origin = typeof window !== "undefined" ? window.location.origin : "";
      if (origin && created.token) {
        setInviteLink(`${origin}/signup/invite?token=${created.token}`);
      }
      setInviteEmail("");
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setSavingInvite(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!token) {
      return;
    }

    const email = user?.email || "your account";
    const ok = window.confirm(`Delete ${email}? This cannot be undone.`);
    if (!ok) {
      return;
    }

    setDeletingAccount(true);
    setError("");
    try {
      await deleteMe(token);
      await logout();
      router.replace("/signup");
    } catch (err) {
      setError(toMessage(err));
    } finally {
      setDeletingAccount(false);
    }
  };

  if (loading) {
    return (
      <div className="grid gap-4">
        <Skeleton className="h-36" />
        <Skeleton className="h-56" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {error ? <ErrorMessage message={error} /> : null}

      <Card className="stagger-item">
        <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle>Workspace Profile</CardTitle>
              <CardDescription>Current authenticated tenant context.</CardDescription>
            </div>
            <Button variant="secondary" size="sm" onClick={load}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent className="pt-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-slate-200/80 bg-slate-50 p-3">
              <p className="text-xs text-slate-500">Email</p>
              <p className="mt-1 text-sm font-medium text-slate-800">{user?.email || "-"}</p>
            </div>
            <div className="rounded-xl border border-slate-200/80 bg-slate-50 p-3">
              <p className="text-xs text-slate-500">Tenant</p>
              <p className="mt-1 text-sm font-medium text-slate-800">
                {activeMembership?.tenant_name || `Tenant ${user?.tenant_id || "-"}`}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200/80 bg-slate-50 p-3">
              <p className="text-xs text-slate-500">Role</p>
              <p className="mt-1 text-sm font-medium text-slate-800">{user?.role || "-"}</p>
            </div>
            <div className="rounded-xl border border-slate-200/80 bg-slate-50 p-3">
              <p className="text-xs text-slate-500">Workspace</p>
              <p className="mt-1 text-sm font-medium text-slate-800">{isPersonal ? "Personal" : "Company"}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="stagger-item border border-rose-200/70">
        <CardHeader className="border-b border-rose-200/60 bg-[linear-gradient(180deg,#fff1f2_0%,#ffffff_100%)]">
          <div>
            <CardTitle className="text-rose-700">Danger Zone</CardTitle>
            <CardDescription>Irreversible actions for your account.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="pt-5">
          <div className="flex flex-col gap-3 rounded-2xl border border-rose-200/70 bg-rose-50/60 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-slate-900">Delete account</p>
              <p className="mt-1 text-xs text-slate-600">
                Permanently deletes your user and removes your workspace memberships.
              </p>
            </div>
            <Button
              type="button"
              variant="danger"
              disabled={deletingAccount}
              onClick={handleDeleteAccount}
              className="sm:shrink-0"
            >
              <Trash2 className="mr-2 h-4 w-4" />
              {deletingAccount ? "Deleting..." : "Delete account"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {!isTenantAdmin ? (
        <Card>
          <CardContent className="pt-5">
            <EmptyState
              title="Limited settings access"
              description="Tenant admin role is required for provider keys, policy, and usage controls."
            />
          </CardContent>
        </Card>
      ) : (
        <>
          <Card className="stagger-item">
            <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
              <div>
                <CardTitle>Provider Configuration</CardTitle>
                <CardDescription>Manage provider keys and model routing for this tenant.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-4 pt-5">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Badge variant="muted">Active provider: {provider?.provider || "none"}</Badge>
                <Badge variant="muted">Model: {provider?.model || "n/a"}</Badge>
                <Badge variant="muted">Source: {provider?.source || "-"}</Badge>
              </div>

              <form
                onSubmit={saveProviderKey}
                className="grid gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/85 p-3.5 lg:grid-cols-5"
              >
                <select
                  value={providerName}
                  onChange={(event) => setProviderName(event.target.value)}
                  className="select-input"
                >
                  {PROVIDERS.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
                <Input
                  placeholder="API key"
                  type="password"
                  value={apiKey}
                  onChange={(event) => setApiKey(event.target.value)}
                  className="lg:col-span-2"
                  required
                />
                <Input
                  placeholder="Model (optional)"
                  value={model}
                  onChange={(event) => setModel(event.target.value)}
                />
                <Input
                  placeholder="Base URL (optional)"
                  value={baseUrl}
                  onChange={(event) => setBaseUrl(event.target.value)}
                />
                <div className="lg:col-span-5">
                  <Button type="submit" disabled={savingKey}>
                    {savingKey ? "Saving..." : "Save Provider Key"}
                  </Button>
                </div>
              </form>

              <form
                onSubmit={saveTavilyKey}
                className="grid gap-3 rounded-2xl border border-amber-100 bg-amber-50/70 p-3.5 lg:grid-cols-4"
              >
                <div className="lg:col-span-3">
                  <Input
                    placeholder="Tavily API key"
                    type="password"
                    value={tavilyApiKey}
                    onChange={(event) => setTavilyApiKey(event.target.value)}
                    required
                  />
                </div>
                <div className="lg:col-span-1">
                  <Button type="submit" disabled={savingTavilyKey} className="w-full">
                    {savingTavilyKey ? "Saving..." : "Save Tavily Key"}
                  </Button>
                </div>
                <p className="lg:col-span-4 text-xs text-amber-700">
                  Optional: use a tenant-specific Tavily key for grounded web search; falls back to the server key if not set.
                </p>
              </form>

              <div className="space-y-2">
                <p className="text-sm font-medium text-slate-700">Stored Keys</p>
                {!keys.length ? (
                  <EmptyState title="No provider keys" description="Add a key to enable model calls for this tenant." />
                ) : (
                  <div className="space-y-2">
                    {keys.map((item) => (
                      <div
                        key={item.provider}
                        className="flex items-center justify-between rounded-xl border border-slate-200/90 bg-white px-3 py-2.5"
                      >
                        <div>
                          <p className="text-sm font-medium text-slate-800">{item.provider}</p>
                          <p className="text-xs text-slate-500">Tail: {item.api_key_tail || "-"}</p>
                        </div>
                        {item.has_key ? (
                          <Button variant="ghost" size="sm" onClick={() => removeKey(item.provider)}>
                            <Trash2 className="mr-1.5 h-4 w-4" />
                            Delete
                          </Button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="stagger-item">
            <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
              <div>
                <CardTitle>Employee Invites</CardTitle>
                <CardDescription>Create invite tokens for employees to join this workspace.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-4 pt-5">
              <form
                onSubmit={saveInvite}
                className="grid gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/80 p-3.5 lg:grid-cols-5"
              >
                <Input
                  placeholder="Employee email (optional)"
                  type="email"
                  value={inviteEmail}
                  onChange={(event) => setInviteEmail(event.target.value)}
                  className="lg:col-span-2"
                />
                <select
                  value={inviteRole}
                  onChange={(event) => setInviteRole(event.target.value)}
                  className="select-input"
                >
                  <option value="employee">employee</option>
                  <option value="tenant_admin">tenant_admin</option>
                </select>
                <select
                  value={inviteType}
                  onChange={(event) => setInviteType(event.target.value as "single" | "multi")}
                  className="select-input"
                >
                  <option value="single">Single-use</option>
                  <option value="multi">Multi-use</option>
                </select>
                <Input
                  type="number"
                  min={1}
                  value={inviteHours}
                  onChange={(event) => setInviteHours(Number(event.target.value))}
                  placeholder="Expires in hours"
                />
                {inviteType === "multi" ? (
                  <Input
                    type="number"
                    min={1}
                    value={inviteMaxUses}
                    onChange={(event) => setInviteMaxUses(Number(event.target.value))}
                    placeholder="Max uses"
                  />
                ) : (
                  <div className="hidden lg:block" />
                )}
                <div className="lg:col-span-5">
                  <Button type="submit" disabled={savingInvite}>
                    {savingInvite ? "Creating invite..." : "Create Invite"}
                  </Button>
                </div>
              </form>

              {inviteResult ? (
                <div className="space-y-2 rounded-2xl border border-emerald-200 bg-emerald-50 p-3.5">
                  <p className="text-sm font-semibold text-emerald-800">Invite created</p>
                  <p className="text-xs text-emerald-700">Token (share securely):</p>
                  <code className="block rounded border border-emerald-200 bg-white px-3 py-2 text-sm text-emerald-900">
                    {inviteResult.token}
                  </code>
                  {inviteLink ? (
                    <div className="space-y-1">
                      <p className="text-xs text-emerald-700">Invite link:</p>
                      <code className="block rounded border border-emerald-200 bg-white px-3 py-2 text-sm text-emerald-900">
                        {inviteLink}
                      </code>
                      <Button
                        type="button"
                        size="sm"
                        variant="secondary"
                        onClick={() => inviteLink && navigator.clipboard?.writeText(inviteLink)}
                      >
                        Copy invite link
                      </Button>
                    </div>
                  ) : null}
                  <p className="text-xs text-emerald-700">
                    Role: {inviteResult.role}; Expires: {inviteResult.expires_at}
                    {inviteResult.max_uses ? `; Max uses: ${inviteResult.max_uses}` : "; Single-use"}
                  </p>
                </div>
              ) : null}
            </CardContent>
          </Card>

          <Card className="stagger-item">
            <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
              <div>
                <CardTitle>Policy Controls</CardTitle>
                <CardDescription>Tenant governance settings for entity categories and blocking threshold.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-5">
              {!canEditPolicy ? (
                <EmptyState
                  title="Policy settings unavailable"
                  description="Company tenant admin access is required for policy controls."
                />
              ) : (
                <form onSubmit={savePolicy} className="grid gap-3 rounded-2xl border border-slate-200/90 bg-slate-50/70 p-3.5 md:grid-cols-2">
                  <label className="space-y-1 text-sm">
                    <span className="field-label">PII action</span>
                    <select
                      value={policy.pii_action}
                      onChange={(event) => setPolicy((p) => ({ ...p, pii_action: event.target.value as PolicyDraft["pii_action"] }))}
                      className="select-input"
                    >
                      <option value="allow">Allow</option>
                      <option value="redact">Redact</option>
                      <option value="block">Block</option>
                    </select>
                  </label>

                  <label className="space-y-1 text-sm">
                    <span className="field-label">Financial action</span>
                    <select
                      value={policy.financial_action}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, financial_action: event.target.value as PolicyDraft["financial_action"] }))
                      }
                      className="select-input"
                    >
                      <option value="allow">Allow</option>
                      <option value="redact">Redact</option>
                      <option value="block">Block</option>
                    </select>
                  </label>

                  <label className="space-y-1 text-sm">
                    <span className="field-label">Secrets action</span>
                    <select
                      value={policy.secrets_action}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, secrets_action: event.target.value as PolicyDraft["secrets_action"] }))
                      }
                      className="select-input"
                    >
                      <option value="allow">Allow</option>
                      <option value="redact">Redact</option>
                      <option value="block">Block</option>
                    </select>
                  </label>

                  <label className="space-y-1 text-sm">
                    <span className="field-label">Health action</span>
                    <select
                      value={policy.health_action}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, health_action: event.target.value as PolicyDraft["health_action"] }))
                      }
                      className="select-input"
                    >
                      <option value="allow">Allow</option>
                      <option value="redact">Redact</option>
                      <option value="block">Block</option>
                    </select>
                  </label>

                  <label className="space-y-1 text-sm">
                    <span className="field-label">IP action</span>
                    <select
                      value={policy.ip_action}
                      onChange={(event) => setPolicy((p) => ({ ...p, ip_action: event.target.value as PolicyDraft["ip_action"] }))}
                      className="select-input"
                    >
                      <option value="allow">Allow</option>
                      <option value="redact">Redact</option>
                      <option value="block">Block</option>
                    </select>
                  </label>

                  <label className="space-y-1 text-sm">
                    <span className="field-label">Block threshold</span>
                    <select
                      value={policy.block_threshold}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, block_threshold: event.target.value as PolicyDraft["block_threshold"] }))
                      }
                      className="select-input"
                    >
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </label>

                  <label className="flex items-center gap-2 rounded-xl border border-slate-200/90 bg-white px-3 py-2.5 text-sm text-slate-700 md:col-span-2">
                    <input
                      type="checkbox"
                      checked={policy.store_original_prompt}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, store_original_prompt: event.target.checked }))
                      }
                    />
                    Store original prompt for audit
                  </label>

                  <label className="flex items-center gap-2 rounded-xl border border-slate-200/90 bg-white px-3 py-2.5 text-sm text-slate-700 md:col-span-2">
                    <input
                      type="checkbox"
                      checked={policy.show_sanitized_prompt_admin}
                      onChange={(event) =>
                        setPolicy((p) => ({ ...p, show_sanitized_prompt_admin: event.target.checked }))
                      }
                    />
                    Show sanitized prompt to tenant admins
                  </label>

                  <div className="md:col-span-2">
                    <Button type="submit" disabled={savingPolicy}>
                      {savingPolicy ? "Saving policy..." : "Save Policy"}
                    </Button>
                  </div>
                </form>
              )}
            </CardContent>
          </Card>

          <Card className="stagger-item">
            <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
              <div>
                <CardTitle>Usage Summary</CardTitle>
                <CardDescription>Daily request and token budget for this tenant.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-5">
              {!usage ? (
                <EmptyState title="Usage unavailable" description="Usage summary is currently unavailable for this account." />
              ) : (
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-xl border border-slate-200/85 bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Daily limit</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{usage.daily_requests_limit}</p>
                  </div>
                  <div className="rounded-xl border border-slate-200/85 bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Today requests</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{usage.today_request_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-200/85 bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Today tokens</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{usage.today_token_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-200/85 bg-slate-50 p-3">
                    <p className="text-xs text-slate-500">Utilization</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{usage.daily_percent_used.toFixed(1)}%</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}


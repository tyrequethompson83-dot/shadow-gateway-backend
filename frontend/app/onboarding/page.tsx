"use client";

import { type FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, RefreshCcw } from "lucide-react";

import { AuthFlowNav } from "@/components/auth/auth-flow-nav";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { bootstrapOnboarding, getOnboardingStatus } from "@/lib/api";
import { errorMessage } from "@/lib/error-utils";
import type { OnboardingBootstrapResponse } from "@/types/api";

const PROVIDERS = ["gemini", "openai", "groq", "anthropic"] as const;
type ProviderName = (typeof PROVIDERS)[number];

function defaultModel(provider: ProviderName): string {
  if (provider === "openai") {
    return "gpt-4.1-mini";
  }
  if (provider === "groq") {
    return "llama-3.1-8b-instant";
  }
  if (provider === "anthropic") {
    return "claude-3-5-haiku-latest";
  }
  return "models/gemini-2.0-flash";
}

function defaultProviderBaseUrl(provider: ProviderName): string {
  return provider === "groq" ? "https://api.groq.com/openai/v1" : "";
}

export default function OnboardingPage() {
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState("");
  const [needsOnboarding, setNeedsOnboarding] = useState(true);

  const [tenantName, setTenantName] = useState("Acme Corp");
  const [adminExternalUser, setAdminExternalUser] = useState("admin.acme");
  const [adminPassword, setAdminPassword] = useState("");
  const [provider, setProvider] = useState<ProviderName>("gemini");
  const [model, setModel] = useState(defaultModel("gemini"));
  const [providerBaseUrl, setProviderBaseUrl] = useState(defaultProviderBaseUrl("gemini"));
  const [apiKey, setApiKey] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [result, setResult] = useState<OnboardingBootstrapResponse | null>(null);

  const refreshStatus = async () => {
    setStatusLoading(true);
    setStatusError("");
    try {
      const payload = await getOnboardingStatus();
      setNeedsOnboarding(Boolean(payload.needs_onboarding));
    } catch (err) {
      setStatusError(errorMessage(err, "Failed to read onboarding status."));
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  const onProviderChange = (nextProvider: ProviderName) => {
    setProvider(nextProvider);
    setModel(defaultModel(nextProvider));
    setProviderBaseUrl(defaultProviderBaseUrl(nextProvider));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitError("");
    setSubmitting(true);
    try {
      const response = await bootstrapOnboarding({
        tenant_name: tenantName.trim(),
        admin_external_user: adminExternalUser.trim(),
        admin_password: adminPassword.trim() || undefined,
        provider,
        model: model.trim() || undefined,
        api_key: apiKey.trim() || undefined,
        base_url: providerBaseUrl.trim() || undefined,
      });
      setResult(response);
      setNeedsOnboarding(false);
    } catch (err) {
      setSubmitError(errorMessage(err, "Onboarding failed."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      cardTitle="First-run onboarding"
      cardDescription="Set up the first tenant, admin user, and provider for this deployment."
      cardClassName="max-w-2xl"
      topSlot={<AuthFlowNav current="onboarding" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          Onboarding done already?{" "}
          <Link href="/login" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Sign in
          </Link>
          .
        </p>
      }
    >
      {statusLoading ? (
        <div className="rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-600">
          Checking onboarding status...
        </div>
      ) : null}

      {!statusLoading && statusError ? <ErrorMessage message={statusError} /> : null}

      {!statusLoading && !statusError && !needsOnboarding ? (
        <div className="space-y-3">
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-3 text-sm text-emerald-800">
            Onboarding is already completed for this environment.
          </div>
          {result ? (
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-3 text-sm text-slate-700">
              <p className="font-semibold text-slate-900">Latest bootstrap result</p>
              <p className="mt-1">Tenant: {result.tenant_name} (ID {result.tenant_id})</p>
              <p className="mt-1">Admin user: {result.admin_external_user}</p>
              <p className="mt-1">Provider: {String(result.provider?.provider || "-")}</p>
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Link
              href="/login"
              className="inline-flex h-8 items-center justify-center rounded-xl bg-[linear-gradient(135deg,#0891b2_0%,#0e7490_100%)] px-3 text-xs font-semibold text-white transition hover:brightness-105"
            >
              Continue to sign in
              <ArrowRight className="ml-2 h-4 w-4" />
            </Link>
            <Button variant="secondary" size="sm" onClick={refreshStatus}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              Refresh status
            </Button>
          </div>
        </div>
      ) : null}

      {!statusLoading && !statusError && needsOnboarding ? (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-3.5 py-2.5 text-sm text-cyan-800">
            No admin membership detected. Complete this once to initialize the deployment.
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="tenantName">
                Tenant name
              </label>
              <Input
                id="tenantName"
                name="tenantName"
                required
                value={tenantName}
                onChange={(event) => setTenantName(event.target.value)}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="adminExternalUser">
                Initial admin user (X-User)
              </label>
              <Input
                id="adminExternalUser"
                name="adminExternalUser"
                required
                value={adminExternalUser}
                onChange={(event) => setAdminExternalUser(event.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="adminPassword">
              Initial admin password (optional for JWT mode)
            </label>
            <Input
              id="adminPassword"
              name="adminPassword"
              type="password"
              autoComplete="new-password"
              value={adminPassword}
              onChange={(event) => setAdminPassword(event.target.value)}
            />
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="provider">
                Provider
              </label>
              <select
                id="provider"
                name="provider"
                className="select-input"
                value={provider}
                onChange={(event) => onProviderChange(event.target.value as ProviderName)}
              >
                {PROVIDERS.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="model">
                Model
              </label>
              <Input id="model" name="model" value={model} onChange={(event) => setModel(event.target.value)} />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="providerBaseUrl">
                Base URL (optional)
              </label>
              <Input
                id="providerBaseUrl"
                name="providerBaseUrl"
                value={providerBaseUrl}
                onChange={(event) => setProviderBaseUrl(event.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="apiKey">
              Provider API key
            </label>
            <Input
              id="apiKey"
              name="apiKey"
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
            />
          </div>

          {submitError ? <ErrorMessage message={submitError} /> : null}

          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Completing onboarding..." : "Complete onboarding"}
              {!submitting ? <ArrowRight className="ml-2 h-4 w-4" /> : null}
            </Button>
            <Button type="button" variant="secondary" onClick={refreshStatus}>
              <RefreshCcw className="mr-2 h-4 w-4" />
              Refresh status
            </Button>
          </div>
        </form>
      ) : null}
    </AuthShell>
  );
}

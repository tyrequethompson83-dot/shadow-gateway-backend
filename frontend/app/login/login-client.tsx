"use client";

import { type FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { AuthFlowNav } from "@/components/auth/auth-flow-nav";
import { AuthShell } from "@/components/auth/auth-shell";
import { useAuth } from "@/hooks/use-auth";
import { errorMessage } from "@/lib/error-utils";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextPath = searchParams.get("next") || "/chat";

  const { login, isAuthenticated, isBooting } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantHint, setTenantHint] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isBooting && isAuthenticated) {
      router.replace(nextPath);
    }
  }, [isBooting, isAuthenticated, nextPath, router]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);

    const tenantId = tenantHint.trim() ? Number(tenantHint.trim()) : undefined;
    if (tenantHint.trim() && (!Number.isInteger(tenantId) || (tenantId ?? 0) <= 0)) {
      setError("Tenant ID must be a positive number.");
      setSubmitting(false);
      return;
    }

    try {
      await login({
        email: email.trim().toLowerCase(),
        password,
        tenantId,
      });
      router.replace(nextPath);
    } catch (err) {
      setError(errorMessage(err, "Unable to sign in. Please verify your credentials."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      cardTitle="Welcome back"
      cardDescription="Sign in to Shadow Gateway to continue."
      cardClassName="max-w-lg"
      topSlot={<AuthFlowNav current="signin" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          New to Shadow Gateway?{" "}
          <Link href="/signup" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Create an account
          </Link>
          .
        </p>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="email">
            Email
          </label>
          <Input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="password">
            Password
          </label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="tenantId">
            Tenant ID (optional)
          </label>
          <Input
            id="tenantId"
            name="tenantId"
            inputMode="numeric"
            placeholder="e.g. 2"
            value={tenantHint}
            onChange={(e) => setTenantHint(e.target.value)}
          />
        </div>

        {error ? <ErrorMessage message={error} /> : null}

        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? "Signing in..." : "Sign in"}
          {!submitting ? <ArrowRight className="ml-2 h-4 w-4" /> : null}
        </Button>
      </form>
    </AuthShell>
  );
}


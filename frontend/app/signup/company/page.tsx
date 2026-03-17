"use client";

import { type FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight } from "lucide-react";

import { AuthFlowNav } from "@/components/auth/auth-flow-nav";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/use-auth";
import { signupCompany } from "@/lib/api";
import { errorMessage } from "@/lib/error-utils";

export default function CompanySignupPage() {
  const router = useRouter();
  const { completeAuth, isAuthenticated, isBooting } = useAuth();

  const [companyName, setCompanyName] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isBooting && isAuthenticated) {
      router.replace("/chat");
    }
  }, [isBooting, isAuthenticated, router]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setSuccess("");
    setSubmitting(true);

    try {
      const auth = await signupCompany({
        company_name: companyName.trim(),
        admin_email: adminEmail.trim().toLowerCase(),
        password,
      });
      setSuccess("Workspace created. Redirecting to your dashboard...");
      await completeAuth(auth);
      router.replace("/chat");
    } catch (err) {
      setError(errorMessage(err, "Unable to create company account."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      cardTitle="Create company account"
      cardDescription="Set up a tenant admin account for your organization."
      cardClassName="max-w-lg"
      topSlot={<AuthFlowNav current="company" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          Prefer a personal workspace?{" "}
          <Link href="/signup/individual" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Sign up as individual
          </Link>
          .
        </p>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="companyName">
            Company name
          </label>
          <Input
            id="companyName"
            name="companyName"
            autoComplete="organization"
            required
            placeholder="Acme Security"
            value={companyName}
            onChange={(event) => setCompanyName(event.target.value)}
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="adminEmail">
            Admin email
          </label>
          <Input
            id="adminEmail"
            name="adminEmail"
            type="email"
            autoComplete="email"
            required
            placeholder="admin@company.com"
            value={adminEmail}
            onChange={(event) => setAdminEmail(event.target.value)}
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
            autoComplete="new-password"
            required
            placeholder="Choose a strong password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {error ? <ErrorMessage message={error} /> : null}
        {success ? (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-sm text-emerald-800">{success}</div>
        ) : null}

        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? "Creating workspace..." : "Create company account"}
          {!submitting ? <ArrowRight className="ml-2 h-4 w-4" /> : null}
        </Button>
      </form>
    </AuthShell>
  );
}

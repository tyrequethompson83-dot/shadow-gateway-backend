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
import { signupIndividual } from "@/lib/api";
import { errorMessage } from "@/lib/error-utils";

export default function IndividualSignupPage() {
  const router = useRouter();
  const { completeAuth, isAuthenticated, isBooting } = useAuth();

  const [label, setLabel] = useState("");
  const [email, setEmail] = useState("");
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
      const auth = await signupIndividual({
        name_or_label: label.trim() || undefined,
        email: email.trim().toLowerCase(),
        password,
      });
      setSuccess("Personal workspace created. Redirecting...");
      await completeAuth(auth);
      router.replace("/chat");
    } catch (err) {
      setError(errorMessage(err, "Unable to create individual account."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      cardTitle="Create individual account"
      cardDescription="Start with your own personal tenant workspace."
      cardClassName="max-w-lg"
      topSlot={<AuthFlowNav current="individual" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          Joining an existing company instead?{" "}
          <Link href="/signup/invite" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Use invite token
          </Link>
          .
        </p>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="label">
            Personal label (optional)
          </label>
          <Input
            id="label"
            name="label"
            autoComplete="nickname"
            placeholder="Solo Builder"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
          />
        </div>

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
            placeholder="you@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
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
          {submitting ? "Creating personal workspace..." : "Create personal account"}
          {!submitting ? <ArrowRight className="ml-2 h-4 w-4" /> : null}
        </Button>
      </form>
    </AuthShell>
  );
}

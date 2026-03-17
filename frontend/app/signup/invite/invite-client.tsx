"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight } from "lucide-react";

import { AuthFlowNav } from "@/components/auth/auth-flow-nav";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/use-auth";
import { signupInvite } from "@/lib/api";
import { errorMessage } from "@/lib/error-utils";

function friendlyInviteError(err: unknown): string {
  const message = errorMessage(err, "Unable to join company with invite token.");
  const lowered = message.toLowerCase();
  if (lowered.includes("already used")) {
    return "Invite link already used.";
  }
  if (lowered.includes("max uses reached")) {
    return "Invite link max uses reached.";
  }
  return message;
}

export default function InviteClient() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { completeAuth, isAuthenticated, isBooting } = useAuth();

  const [inviteToken, setInviteToken] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const seededToken = useMemo(() => {
    const direct = (searchParams.get("token") || "").trim();
    if (direct) {
      return direct;
    }
    return (searchParams.get("join") || "").trim();
  }, [searchParams]);

  useEffect(() => {
    if (seededToken) {
      setInviteToken((current) => (current.trim() ? current : seededToken));
    }
  }, [seededToken]);

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
      const auth = await signupInvite({
        token: inviteToken.trim(),
        email: email.trim().toLowerCase(),
        password,
      });
      setSuccess("Invite accepted. Redirecting to your workspace...");
      await completeAuth(auth);
      router.replace("/chat");
    } catch (err) {
      setError(friendlyInviteError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      cardTitle="Join with invite token"
      cardDescription="Use your company invite to create credentials and join a tenant."
      cardClassName="max-w-lg"
      topSlot={<AuthFlowNav current="invite" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          Need a new workspace instead?{" "}
          <Link href="/signup/company" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Create company account
          </Link>
          .
        </p>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {seededToken ? (
          <div className="rounded-xl border border-cyan-200 bg-cyan-50 px-3.5 py-2.5 text-xs font-medium text-cyan-800">
            Invite token pre-filled from link.
          </div>
        ) : null}

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="inviteToken">
            Invite token
          </label>
          <Input
            id="inviteToken"
            name="inviteToken"
            required
            placeholder="Paste token from your workspace admin"
            value={inviteToken}
            onChange={(event) => setInviteToken(event.target.value)}
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-700" htmlFor="email">
            Work email
          </label>
          <Input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            placeholder="you@company.com"
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
            placeholder="Create your password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {error ? <ErrorMessage message={error} /> : null}
        {success ? (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-sm text-emerald-800">{success}</div>
        ) : null}

        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? "Joining company..." : "Join company"}
          {!submitting ? <ArrowRight className="ml-2 h-4 w-4" /> : null}
        </Button>
      </form>
    </AuthShell>
  );
}

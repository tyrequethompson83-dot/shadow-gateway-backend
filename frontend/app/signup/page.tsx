"use client";

import Link from "next/link";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Building2, Ticket, UserRound } from "lucide-react";

import { AuthFlowNav } from "@/components/auth/auth-flow-nav";
import { AuthShell } from "@/components/auth/auth-shell";
import { useAuth } from "@/hooks/use-auth";

type FlowCard = {
  href: string;
  title: string;
  description: string;
  icon: typeof Building2;
};

const FLOW_CARDS: FlowCard[] = [
  {
    href: "/signup/company",
    title: "Create company workspace",
    description: "Create a tenant admin account for a shared company workspace.",
    icon: Building2,
  },
  {
    href: "/signup/individual",
    title: "Create individual workspace",
    description: "Start with a personal workspace that is isolated to your account.",
    icon: UserRound,
  },
  {
    href: "/signup/invite",
    title: "Join with invite token",
    description: "Use a team invite token to join an existing company tenant.",
    icon: Ticket,
  },
];

export default function SignupLandingPage() {
  const router = useRouter();
  const { isAuthenticated, isBooting } = useAuth();

  useEffect(() => {
    if (!isBooting && isAuthenticated) {
      router.replace("/chat");
    }
  }, [isBooting, isAuthenticated, router]);

  return (
    <AuthShell
      cardTitle="Create account"
      cardDescription="Choose the onboarding path that matches your workspace."
      cardClassName="max-w-2xl"
      topSlot={<AuthFlowNav current="create" />}
      footerSlot={
        <p className="text-sm text-slate-600">
          Already have credentials?{" "}
          <Link href="/login" className="font-semibold text-cyan-700 hover:text-cyan-800">
            Sign in
          </Link>
          .
        </p>
      }
    >
      <div className="grid gap-3 sm:grid-cols-3">
        {FLOW_CARDS.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className="group rounded-2xl border border-slate-200 bg-white p-4 text-left transition hover:border-cyan-300 hover:bg-cyan-50/40"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-50 text-cyan-700">
                <Icon className="h-5 w-5" />
              </div>
              <p className="mt-3 text-sm font-semibold text-slate-900">{item.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-slate-600">{item.description}</p>
              <p className="mt-3 inline-flex items-center text-xs font-semibold text-cyan-700">
                Continue <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </p>
            </Link>
          );
        })}
      </div>
    </AuthShell>
  );
}

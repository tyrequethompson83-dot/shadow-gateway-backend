import Link from "next/link";

import { cn } from "@/lib/cn";

const FLOW_DEFS = {
  signin: { href: "/login", label: "Sign in" },
  create: { href: "/signup", label: "Create account" },
  company: { href: "/signup/company", label: "Company signup" },
  individual: { href: "/signup/individual", label: "Individual signup" },
  invite: { href: "/signup/invite", label: "Join with invite" },
  onboarding: { href: "/onboarding", label: "First-run onboarding" },
} as const;

export type AuthFlowId = keyof typeof FLOW_DEFS;

type AuthFlowNavProps = {
  current: AuthFlowId;
  items?: AuthFlowId[];
};

export function AuthFlowNav({ current, items }: AuthFlowNavProps) {
  const visibleItems = items ?? ["signin", "create", "company", "individual", "invite", "onboarding"];

  return (
    <nav className="flex flex-wrap gap-2" aria-label="Authentication navigation">
      {visibleItems.map((id) => {
        const item = FLOW_DEFS[id];
        const active = id === current;
        return (
          <Link
            key={id}
            href={item.href}
            className={cn(
              "rounded-full border px-3 py-1.5 text-xs font-semibold transition",
              active
                ? "border-cyan-200 bg-cyan-50 text-cyan-700"
                : "border-slate-200 text-slate-600 hover:border-cyan-200 hover:bg-cyan-50/50 hover:text-cyan-700",
            )}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

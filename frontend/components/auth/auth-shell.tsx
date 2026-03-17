"use client";

import type { ReactNode } from "react";
import { Building2, LockKeyhole, Shield } from "lucide-react";

import { cn } from "@/lib/cn";
import { getApiBaseUrl } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type AuthShellProps = {
  cardTitle: string;
  cardDescription: string;
  children: ReactNode;
  topSlot?: ReactNode;
  footerSlot?: ReactNode;
  cardClassName?: string;
};

export function AuthShell({
  cardTitle,
  cardDescription,
  children,
  topSlot,
  footerSlot,
  cardClassName,
}: AuthShellProps) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-950 px-4 py-8 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_18%,rgba(34,211,238,0.35)_0%,transparent_34%),radial-gradient(circle_at_82%_10%,rgba(14,165,233,0.28)_0%,transparent_32%)]" />
      <div className="relative mx-auto flex min-h-[90vh] w-full max-w-6xl items-stretch overflow-hidden rounded-3xl border border-slate-800 bg-slate-900/85 shadow-[0_40px_80px_rgba(2,8,23,0.45)] backdrop-blur">
        <section className="hidden w-[45%] flex-col justify-between border-r border-slate-800 bg-[linear-gradient(155deg,#0f172a_0%,#0a2640_55%,#093046_100%)] p-10 text-slate-100 lg:flex">
          <div>
            <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-white/10 text-lg font-bold">SG</div>
            <h1 className="font-heading mt-8 text-4xl font-semibold leading-tight">Shadow AI Gateway</h1>
            <p className="mt-4 text-sm leading-relaxed text-slate-300">
              Secure tenant-aware AI operations with policy enforcement, risk controls, and provider routing.
            </p>
          </div>

          <div className="space-y-3 text-sm text-slate-200">
            <div className="flex items-center gap-2 rounded-xl bg-white/5 px-3 py-2">
              <Shield className="h-4 w-4 text-cyan-200" />
              <span>JWT auth and tenant isolation</span>
            </div>
            <div className="flex items-center gap-2 rounded-xl bg-white/5 px-3 py-2">
              <Building2 className="h-4 w-4 text-cyan-200" />
              <span>Company and personal workspace onboarding</span>
            </div>
            <div className="flex items-center gap-2 rounded-xl bg-white/5 px-3 py-2">
              <LockKeyhole className="h-4 w-4 text-cyan-200" />
              <span>API endpoint: {getApiBaseUrl()}</span>
            </div>
          </div>
        </section>

        <section className="flex w-full items-center justify-center bg-white px-6 py-10 sm:px-10 lg:w-[55%]">
          <Card className={cn("w-full border-slate-200/90", cardClassName)}>
            <CardHeader className="space-y-4">
              {topSlot ? <div className="w-full">{topSlot}</div> : null}
              <div>
                <CardTitle>{cardTitle}</CardTitle>
                <CardDescription className="mt-1">{cardDescription}</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {children}
              {footerSlot ? <div className="border-t border-slate-200 pt-4">{footerSlot}</div> : null}
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
}

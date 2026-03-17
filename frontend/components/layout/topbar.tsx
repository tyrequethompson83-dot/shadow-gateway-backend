"use client";

import { Bell, CalendarDays, Cloud, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { PAGE_TITLES } from "@/lib/navigation";

export function Topbar({ pathname }: { pathname: string }) {
  const title = PAGE_TITLES[pathname] ?? "Shadow Gateway";
  const today = new Date().toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  return (
    <header className="sticky top-0 z-20 border-b border-slate-200/70 bg-white/90 backdrop-blur">
      <div className="flex h-[78px] items-center justify-between px-5 sm:px-6 lg:px-8">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">Shadow Gateway</p>
          <h1 className="font-heading mt-1 text-[1.75rem] font-semibold tracking-tight text-slate-950">{title}</h1>
          <p className="mt-1 text-sm text-slate-500">Multi-tenant AI governance workspace</p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="hidden items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-600 md:inline-flex">
            <CalendarDays className="h-3.5 w-3.5 text-slate-500" />
            <span>{today}</span>
          </div>
          <Button variant="secondary" size="sm" className="hidden md:inline-flex">
            <Cloud className="mr-1.5 h-4 w-4 text-cyan-700" />
            API Connected
          </Button>
          <Button variant="secondary" size="sm" className="w-8 px-0">
            <Bell className="h-4 w-4" />
          </Button>
          <Button variant="secondary" size="sm" className="w-8 px-0">
            <Sparkles className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}


import * as React from "react";

import { cn } from "@/lib/cn";

type BadgeVariant = "default" | "muted" | "success" | "warning" | "danger";

const classesByVariant: Record<BadgeVariant, string> = {
  default: "border border-cyan-200/80 bg-cyan-50 text-cyan-800",
  muted: "border border-slate-200/80 bg-slate-100/80 text-slate-700",
  success: "border border-emerald-200/80 bg-emerald-50 text-emerald-700",
  warning: "border border-amber-200/80 bg-amber-50 text-amber-700",
  danger: "border border-rose-200/80 bg-rose-50 text-rose-700",
};

export function Badge({
  className,
  variant = "default",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: BadgeVariant }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold tracking-[0.02em]",
        classesByVariant[variant],
        className,
      )}
      {...props}
    />
  );
}


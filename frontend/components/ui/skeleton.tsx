import { cn } from "@/lib/cn";

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-xl bg-gradient-to-r from-slate-200/70 via-slate-100/85 to-slate-200/70",
        className,
      )}
    />
  );
}


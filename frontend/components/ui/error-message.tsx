import { AlertCircle } from "lucide-react";

import { cn } from "@/lib/cn";

export function ErrorMessage({
  message,
  className,
}: {
  message: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-start gap-2 rounded-xl border border-rose-200/90 bg-gradient-to-r from-rose-50 to-rose-100/70 px-3.5 py-2.5 text-sm text-rose-800 shadow-sm",
        className,
      )}
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
      <p>{message}</p>
    </div>
  );
}


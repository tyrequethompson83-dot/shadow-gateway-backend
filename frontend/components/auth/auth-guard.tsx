"use client";

import { type ReactNode, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";

import { useAuth } from "@/hooks/use-auth";
import { Skeleton } from "@/components/ui/skeleton";

export function AuthGuard({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { isBooting, isAuthenticated } = useAuth();

  useEffect(() => {
    if (isBooting) {
      return;
    }
    if (!isAuthenticated) {
      const next = pathname && pathname !== "/" ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${next}`);
    }
  }, [isBooting, isAuthenticated, router, pathname]);

  if (isBooting || !isAuthenticated) {
    return (
      <div className="flex min-h-screen bg-slate-100 p-6 lg:p-8">
        <div className="hidden w-[286px] shrink-0 lg:block">
          <Skeleton className="h-full w-full rounded-3xl" />
        </div>
        <div className="w-full space-y-4 lg:pl-7">
          <Skeleton className="h-20 w-full rounded-3xl" />
          <Skeleton className="h-[420px] w-full rounded-3xl" />
        </div>
      </div>
    );
  }

  return <>{children}</>;
}


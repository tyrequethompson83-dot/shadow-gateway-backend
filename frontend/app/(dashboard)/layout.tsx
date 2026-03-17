"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";

import { AuthGuard } from "@/components/auth/auth-guard";
import { Sidebar } from "@/components/layout/sidebar";
import { ChatHistoryProvider } from "@/components/providers/chat-history-provider";
import { Topbar } from "@/components/layout/topbar";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <AuthGuard>
      <ChatHistoryProvider>
        <div className="flex min-h-screen">
          <Sidebar />
          <div className="min-w-0 flex-1 bg-transparent">
            <Topbar pathname={pathname} />
            <main className="px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
              <div className="mx-auto w-full max-w-[1340px]">{children}</div>
            </main>
          </div>
        </div>
      </ChatHistoryProvider>
    </AuthGuard>
  );
}


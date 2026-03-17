"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Building2, LogOut, MessageSquareText, MoreHorizontal, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { useAuth } from "@/hooks/use-auth";
import { useChatHistory } from "@/components/providers/chat-history-provider";
import { NAV_ITEMS, TEAM_CHAT_ROUTE } from "@/lib/navigation";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";

function formatConversationTime(timestamp: number): string {
  if (!timestamp) {
    return "";
  }
  return new Date(timestamp).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout } = useAuth();
  const {
    conversations,
    activeConversationId,
    historyLoading,
    setActiveConversationId,
    startNewChat,
    deleteConversation,
  } = useChatHistory();

  const initials = (user?.email ?? "U").slice(0, 1).toUpperCase();
  const [openMenuConversationId, setOpenMenuConversationId] = useState<string | null>(null);

  const handleLogout = async () => {
    await logout();
    router.replace("/login");
  };

  const openConversation = (conversationId: string) => {
    setActiveConversationId(conversationId);
    if (pathname !== TEAM_CHAT_ROUTE) {
      router.push(TEAM_CHAT_ROUTE);
    }
  };

  const handleNewChat = () => {
    startNewChat();
    if (pathname !== TEAM_CHAT_ROUTE) {
      router.push(TEAM_CHAT_ROUTE);
    }
  };

  useEffect(() => {
    if (!openMenuConversationId) {
      return;
    }

    const close = () => setOpenMenuConversationId(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [openMenuConversationId]);

  return (
    <aside className="relative hidden h-screen w-[286px] shrink-0 flex-col overflow-hidden border-r border-slate-800/80 bg-[linear-gradient(165deg,#0f1f4d_0%,#0b1530_48%,#070d1d_100%)] px-5 py-6 text-slate-200 lg:flex">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_12%_8%,rgba(56,189,248,0.22)_0%,rgba(56,189,248,0)_34%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(150deg,rgba(255,255,255,0.06)_0%,transparent_36%)]" />

      <div className="relative rounded-2xl border border-white/15 bg-white/5 px-3 py-3 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400/70 to-sky-500/40 text-base font-bold text-white shadow-[0_8px_24px_rgba(8,145,178,0.35)]">
            SG
          </div>
          <div>
            <p className="font-heading text-lg font-semibold leading-none text-white">Shadow Gateway</p>
            <p className="mt-1 text-xs text-slate-300">AI Governance Console</p>
          </div>
        </div>
        <div>
          <div className="mt-3 inline-flex items-center gap-1 rounded-full border border-cyan-300/25 bg-cyan-400/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.09em] text-cyan-100">
            <Building2 className="h-3 w-3" />
            Enterprise Workspace
          </div>
        </div>
      </div>

      <div className="relative mt-5 flex min-h-0 flex-1 flex-col">
        <Button
          onClick={handleNewChat}
          className="w-full justify-start border border-cyan-200/30 bg-[linear-gradient(140deg,#06b6d4_0%,#0284c7_100%)] text-white shadow-[0_12px_30px_rgba(2,132,199,0.35)] hover:brightness-110"
        >
          <Plus className="mr-2 h-4 w-4" />
          New Chat
        </Button>

        <div className="mt-4 flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-white/15 bg-white/5 backdrop-blur">
          <div className="flex items-center justify-between border-b border-white/10 px-3 py-2.5">
            <div className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-300">
              <MessageSquareText className="h-3.5 w-3.5 text-cyan-200" />
              Recent Conversations
            </div>
            {!historyLoading ? (
              <span className="rounded-full border border-white/20 bg-white/5 px-2 py-0.5 text-[10px] text-slate-300">
                {conversations.length}
              </span>
            ) : null}
          </div>

          <div className="app-scroll min-h-0 flex-1 space-y-1.5 overflow-y-auto p-2">
            {historyLoading ? (
              <div className="space-y-1.5">
                <div className="h-14 rounded-xl border border-white/10 bg-white/5" />
                <div className="h-14 rounded-xl border border-white/10 bg-white/5" />
                <div className="h-14 rounded-xl border border-white/10 bg-white/5" />
              </div>
            ) : conversations.length ? (
              conversations.map((conversation) => {
                const active = conversation.id === activeConversationId;
                const latest = conversation.messages[conversation.messages.length - 1];
                return (
                  <div
                    key={conversation.id}
                    onClick={() => openConversation(conversation.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        openConversation(conversation.id);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    className={cn(
                      "group relative w-full rounded-xl border px-2.5 py-2 text-left transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-200/40",
                      active
                        ? "border-cyan-300/35 bg-gradient-to-r from-cyan-500/18 to-sky-500/6 text-white ring-1 ring-cyan-200/20"
                        : "border-white/10 bg-white/5 text-slate-200 hover:border-white/25 hover:bg-white/10",
                    )}
                  >
                    <div className="pr-7">
                      <p className="truncate text-sm font-semibold">{conversation.title}</p>
                      <p className={cn("mt-0.5 truncate text-xs", active ? "text-cyan-100/90" : "text-slate-400")}>
                        {latest?.content || "No messages yet"}
                      </p>
                      <p className={cn("mt-0.5 text-[11px]", active ? "text-cyan-100/70" : "text-slate-500")}>
                        {formatConversationTime(conversation.updatedAt)}
                      </p>
                    </div>

                    <div className="absolute right-2 top-2">
                      <button
                        type="button"
                        title="Conversation options"
                        aria-label="Conversation options"
                        className={cn(
                          "flex h-7 w-7 items-center justify-center rounded-lg border border-white/15 bg-white/5 text-slate-200 opacity-0 shadow-sm transition-all hover:bg-white/10 group-hover:opacity-100",
                          openMenuConversationId === conversation.id ? "opacity-100" : "",
                        )}
                        onClick={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          setOpenMenuConversationId((current) => (current === conversation.id ? null : conversation.id));
                        }}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </button>

                      {openMenuConversationId === conversation.id ? (
                        <div
                          role="menu"
                          className="absolute right-0 z-50 mt-2 w-40 overflow-hidden rounded-xl border border-white/15 bg-[#0b1530] shadow-[0_18px_40px_rgba(0,0,0,0.45)]"
                          onClick={(event) => {
                            event.preventDefault();
                            event.stopPropagation();
                          }}
                        >
                          <button
                            type="button"
                            role="menuitem"
                            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-rose-200 transition-colors hover:bg-white/10"
                            onClick={() => {
                              setOpenMenuConversationId(null);
                              const ok = window.confirm("Delete this chat? This cannot be undone.");
                              if (!ok) {
                                return;
                              }
                              deleteConversation(conversation.id);
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                            Delete chat
                          </button>
                        </div>
                      ) : null}
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="rounded-xl border border-dashed border-white/15 bg-white/[0.03] px-3 py-4 text-center text-xs text-slate-400">
                No conversations yet. Start a new chat.
              </p>
            )}
          </div>
        </div>

        <nav className="mt-4 space-y-1.5 border-t border-white/10 pt-4">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "group flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all duration-200",
                  active
                    ? "bg-gradient-to-r from-cyan-500/18 to-sky-500/5 text-white ring-1 ring-cyan-300/30"
                    : "text-slate-300 hover:bg-white/10 hover:text-white",
                )}
              >
                <span
                  className={cn(
                    "inline-block h-6 w-0.5 rounded-full transition-all",
                    active ? "bg-cyan-300" : "bg-transparent group-hover:bg-white/20",
                  )}
                />
                <Icon
                  className={cn("h-4 w-4", active ? "text-cyan-200" : "text-slate-400 group-hover:text-slate-100")}
                />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div className="relative mt-5 rounded-2xl border border-white/15 bg-white/5 p-3 backdrop-blur">
        <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-2.5 py-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-700/80 text-xs font-semibold">
            {initials}
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-white">{user?.email ?? "Unknown user"}</p>
            <div className="mt-1 flex items-center gap-1 text-xs text-slate-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>{user?.role ?? "member"}</span>
            </div>
          </div>
        </div>

        <Button
          variant="ghost"
          className="mt-3 w-full justify-center border border-white/20 bg-transparent text-slate-100 hover:bg-white/10"
          onClick={handleLogout}
        >
          <LogOut className="mr-2 h-4 w-4" />
          Logout
        </Button>
      </div>
    </aside>
  );
}


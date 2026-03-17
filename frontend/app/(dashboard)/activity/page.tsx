"use client";

import { useEffect, useMemo, useState } from "react";
import { ListFilter, Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorMessage } from "@/components/ui/error-message";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { ApiError, getActivity } from "@/lib/api";
import type { ActivityItem } from "@/types/api";

function formatTimestamp(ts: string): string {
  if (!ts) {
    return "-";
  }
  const parsed = new Date(ts);
  if (Number.isNaN(parsed.getTime())) {
    return ts;
  }
  return parsed.toLocaleString();
}

function decisionVariant(decision: string): "success" | "warning" | "danger" | "muted" {
  const value = decision.toUpperCase();
  if (value === "ALLOW") {
    return "success";
  }
  if (value === "REDACT") {
    return "warning";
  }
  if (value === "BLOCK") {
    return "danger";
  }
  return "muted";
}

function parseError(err: unknown): string {
  if (err instanceof ApiError) {
    if (typeof err.detail === "string") {
      return err.detail;
    }
    if (err.detail && typeof err.detail === "object" && "detail" in err.detail) {
      const detail = (err.detail as { detail?: unknown }).detail;
      if (typeof detail === "string") {
        return detail;
      }
    }
  }
  if (err instanceof Error) {
    return err.message;
  }
  return "Unable to load activity feed.";
}

export default function ActivityPage() {
  const { token } = useAuth();

  const [items, setItems] = useState<ActivityItem[]>([]);
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      if (!token) {
        return;
      }
      setLoading(true);
      setError("");
      try {
        const payload = await getActivity(token, 120);
        if (!active) {
          return;
        }
        setItems(payload.items || []);
      } catch (err) {
        if (!active) {
          return;
        }
        setError(parseError(err));
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    load();
    return () => {
      active = false;
    };
  }, [token]);

  const filtered = useMemo(() => {
    return items.filter((item) => {
      if (decision !== "all" && item.decision.toLowerCase() !== decision) {
        return false;
      }
      const haystack = `${item.user} ${item.purpose ?? ""} ${item.provider ?? ""} ${item.model ?? ""}`.toLowerCase();
      if (!query.trim()) {
        return true;
      }
      return haystack.includes(query.trim().toLowerCase());
    });
  }, [items, decision, query]);

  return (
    <div className="space-y-5">
      <Card className="stagger-item">
        <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
          <div className="flex w-full items-start justify-between gap-3">
            <div>
            <CardTitle>Activity Feed</CardTitle>
            <CardDescription>Recent tenant-governed requests and policy decisions.</CardDescription>
            </div>
            <Badge variant="muted">{filtered.length} records</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 pt-5">
          <div className="surface-muted flex flex-col gap-3 p-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by user, purpose, provider..."
                className="pl-9"
              />
            </div>

            <select
              value={decision}
              onChange={(event) => setDecision(event.target.value)}
              className="select-input sm:w-[180px]"
            >
              <option value="all">All decisions</option>
              <option value="allow">Allow</option>
              <option value="redact">Redact</option>
              <option value="block">Block</option>
            </select>
            <div className="hidden items-center gap-1 text-xs font-medium text-slate-500 sm:inline-flex">
              <ListFilter className="h-3.5 w-3.5" />
              Filtered view
            </div>
          </div>

          {error ? <ErrorMessage message={error} /> : null}

          {loading ? (
            <div className="space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              title="No activity records"
              description="Try broadening filters or generate activity from Team Chat."
            />
          ) : (
            <div className="app-scroll overflow-x-auto rounded-2xl border border-slate-200">
              <table className="w-full min-w-[860px] border-collapse text-sm">
                <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3 font-medium">Timestamp</th>
                    <th className="px-4 py-3 font-medium">User</th>
                    <th className="px-4 py-3 font-medium">Purpose</th>
                    <th className="px-4 py-3 font-medium">Decision</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                    <th className="px-4 py-3 font-medium">Provider</th>
                    <th className="px-4 py-3 font-medium">Request ID</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item) => (
                    <tr key={item.id} className="border-t border-slate-200/80 text-slate-700 transition-colors hover:bg-slate-50/70">
                      <td className="whitespace-nowrap px-4 py-3">{formatTimestamp(item.ts)}</td>
                      <td className="px-4 py-3">{item.user || "-"}</td>
                      <td className="px-4 py-3">{item.purpose || "-"}</td>
                      <td className="px-4 py-3">
                        <Badge variant={decisionVariant(item.decision)}>{item.decision}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        {item.risk_level || "UNKNOWN"} ({Number(item.risk_score || 0).toFixed(1)})
                      </td>
                      <td className="px-4 py-3">
                        {item.provider || "-"}
                        {item.model ? `:${item.model}` : ""}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{item.id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}


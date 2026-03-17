"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, BarChart3, ShieldCheck, Waves } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorMessage } from "@/components/ui/error-message";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { getAnalytics } from "@/lib/api";
import type { AnalyticsResponse } from "@/types/api";

function Sparkline({ points }: { points: number[] }) {
  if (!points.length) {
    return <div className="h-[170px] rounded-xl bg-slate-50" />;
  }

  const width = 720;
  const height = 170;
  const padding = 18;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const span = Math.max(1, max - min);

  const toPoint = (value: number, idx: number) => {
    const x = padding + (idx / Math.max(1, points.length - 1)) * (width - padding * 2);
    const y = height - padding - ((value - min) / span) * (height - padding * 2);
    return `${x},${y}`;
  };

  const polylinePoints = points.map((value, idx) => toPoint(value, idx)).join(" ");
  const areaPoints = `${padding},${height - padding} ${polylinePoints} ${width - padding},${height - padding}`;
  const guideLines = [0.2, 0.45, 0.7].map((ratio) => height - padding - ratio * (height - padding * 2));

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-[170px] w-full rounded-xl bg-slate-50">
      <defs>
        <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#0891b2" stopOpacity="0.34" />
          <stop offset="100%" stopColor="#0891b2" stopOpacity="0" />
        </linearGradient>
      </defs>
      {guideLines.map((line) => (
        <line key={line} x1={padding} y1={line} x2={width - padding} y2={line} stroke="#dbe6f1" strokeDasharray="4 6" />
      ))}
      <polygon points={areaPoints} fill="url(#riskGradient)" />
      <polyline points={polylinePoints} fill="none" stroke="#0891b2" strokeWidth="3" strokeLinejoin="round" />
    </svg>
  );
}

function topEntries(source: Record<string, number>, limit = 6): Array<[string, number]> {
  return Object.entries(source || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
}

function percent(value: number, total: number): string {
  if (!total) {
    return "0%";
  }
  return `${((value / total) * 100).toFixed(1)}%`;
}

export default function AnalyticsPage() {
  const { token } = useAuth();

  const [data, setData] = useState<AnalyticsResponse | null>(null);
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
        const payload = await getAnalytics(token, 30);
        if (active) {
          setData(payload);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Failed to load analytics.");
        }
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

  const trendPoints = useMemo(
    () => (data?.risk_trend ?? []).map((row) => Number(row.avg_risk || 0)),
    [data],
  );

  const entityRows = useMemo(() => topEntries(data?.entity_totals ?? {}), [data]);
  const providerRows = useMemo(() => topEntries(data?.compliance?.provider_usage ?? {}), [data]);

  const totalRequests = Number(data?.summary?.total_requests ?? 0);
  const blocked = Number(data?.compliance?.blocked ?? 0);
  const redacted = Number(data?.compliance?.redacted ?? 0);

  return (
    <div className="space-y-5">
      {error ? <ErrorMessage message={error} /> : null}

      {loading ? (
        <div className="grid gap-4 lg:grid-cols-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : null}

      {!loading && !data ? (
        <EmptyState title="No analytics data" description="Start using Team Chat to generate tenant analytics." />
      ) : null}

      {data ? (
        <>
          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Card className="stagger-item">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardDescription>Total Requests</CardDescription>
                  <BarChart3 className="h-4 w-4 text-cyan-700" />
                </div>
                <CardTitle className="text-3xl">{data.summary.total_requests}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="stagger-item">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardDescription>Average Risk Score</CardDescription>
                  <Waves className="h-4 w-4 text-cyan-700" />
                </div>
                <CardTitle className="text-3xl">{data.summary.avg_risk_score.toFixed(2)}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="stagger-item">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardDescription>High or Critical</CardDescription>
                  <AlertTriangle className="h-4 w-4 text-amber-600" />
                </div>
                <CardTitle className="text-3xl">{data.summary.high_or_critical}</CardTitle>
              </CardHeader>
            </Card>
            <Card className="stagger-item">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardDescription>Today Usage</CardDescription>
                  <ShieldCheck className="h-4 w-4 text-emerald-600" />
                </div>
                <CardTitle className="text-3xl">{data.usage.daily_percent_used.toFixed(1)}%</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-slate-500">
                  {data.usage.today_request_count}/{data.usage.daily_requests_limit} requests
                </p>
              </CardContent>
            </Card>
          </section>

          <section className="grid gap-4 xl:grid-cols-[2fr_1fr]">
            <Card className="stagger-item">
              <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)]">
                <div>
                  <CardTitle>Risk Trend</CardTitle>
                  <CardDescription>Average request risk score over recent days.</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="pt-5">
                {(data.risk_trend ?? []).length === 0 ? (
                  <EmptyState
                    title="No trend data"
                    description="Trend chart appears once requests are logged for this tenant."
                  />
                ) : (
                  <>
                    <Sparkline points={trendPoints} />
                    <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500">
                      {data.risk_trend.map((row) => (
                        <Badge key={row.date} variant="muted">
                          {row.date}: {Number(row.avg_risk || 0).toFixed(1)}
                        </Badge>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card className="stagger-item">
              <CardHeader>
                <div>
                  <CardTitle>Decision Mix</CardTitle>
                  <CardDescription>Policy outcomes for tenant traffic.</CardDescription>
                </div>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex items-center justify-between rounded-xl border border-emerald-100 bg-emerald-50 px-3 py-2.5">
                  <span>Allowed</span>
                  <span>
                    {data.compliance.allowed} ({percent(data.compliance.allowed, totalRequests)})
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-amber-100 bg-amber-50 px-3 py-2.5">
                  <span>Redacted</span>
                  <span>
                    {redacted} ({percent(redacted, totalRequests)})
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-rose-100 bg-rose-50 px-3 py-2.5">
                  <span>Blocked</span>
                  <span>
                    {blocked} ({percent(blocked, totalRequests)})
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50 px-3 py-2.5">
                  <span>Injection Attempts</span>
                  <span>{data.compliance.injection_attempts}</span>
                </div>
              </CardContent>
            </Card>
          </section>

          <section className="grid gap-4 xl:grid-cols-2">
            <Card className="stagger-item">
              <CardHeader>
                <div>
                  <CardTitle>Entity Breakdown</CardTitle>
                  <CardDescription>Top detected entity categories.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                {entityRows.length === 0 ? (
                  <EmptyState title="No entities" description="No entity detections are available yet." />
                ) : (
                  <div className="space-y-2.5">
                    {entityRows.map(([name, value]) => {
                      const width = totalRequests ? Math.max(5, Math.min(100, (value / totalRequests) * 100)) : 0;
                      return (
                        <div key={name}>
                          <div className="mb-1 flex items-center justify-between text-sm">
                            <span className="text-slate-700">{name}</span>
                            <span className="text-slate-500">{value}</span>
                          </div>
                          <div className="h-2.5 rounded-full bg-slate-100">
                            <div
                              className="h-2.5 rounded-full bg-[linear-gradient(90deg,#0891b2_0%,#0ea5e9_100%)]"
                              style={{ width: `${width}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="stagger-item">
              <CardHeader>
                <div>
                  <CardTitle>Provider Usage</CardTitle>
                  <CardDescription>Request volume by active provider.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                {providerRows.length === 0 ? (
                  <EmptyState title="No provider data" description="Provider usage appears after successful calls." />
                ) : (
                  <div className="space-y-2">
                    {providerRows.map(([name, value]) => (
                      <div
                        key={name}
                        className="flex items-center justify-between rounded-xl border border-slate-200/85 bg-slate-50 px-3 py-2.5 text-sm"
                      >
                        <span>{name}</span>
                        <span className="font-medium text-slate-700">{value}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </section>
        </>
      ) : null}
    </div>
  );
}


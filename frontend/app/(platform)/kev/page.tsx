'use client';

import { useQuery } from '@tanstack/react-query';
import { kevApi } from '@/lib/api/client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Search, Filter, RefreshCw, TrendingUp, Shield, Zap, Clock } from 'lucide-react';
import { format } from 'date-fns';
import { clsx } from 'clsx';
import { KEVVendorChart } from '@/components/charts/KEVVendorChart';

function EPSSBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-text-muted text-xs">—</span>;
  const pct = Math.round(score * 100);
  const color = pct >= 70 ? 'text-severity-critical' : pct >= 30 ? 'text-severity-high' : 'text-severity-low';
  return <span className={clsx('font-mono text-xs font-semibold', color)}>{pct}%</span>;
}

function CVSSBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-text-muted text-xs">—</span>;
  const color = score >= 9 ? 'badge-critical' : score >= 7 ? 'badge-high' : score >= 4 ? 'badge-medium' : 'badge-low';
  return <span className={clsx('text-xs font-mono px-1.5 py-0.5 rounded border', color)}>{score.toFixed(1)}</span>;
}

export default function KEVPage() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState('');
  const [vendor, setVendor] = useState('');
  const [knownRansomware, setKnownRansomware] = useState<boolean | null>(null);
  const [sortBy, setSortBy] = useState('date_added');

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['kev', { page, q, vendor, knownRansomware, sortBy }],
    queryFn: () => kevApi.list({
      page, page_size: 25, q: q || undefined,
      vendor: vendor || undefined,
      known_ransomware: knownRansomware ?? undefined,
      sort_by: sortBy, sort_order: 'desc',
    }).then(r => r.data),
    keepPreviousData: true,
  } as any);

  const { data: stats } = useQuery({
    queryKey: ['kev', 'stats'],
    queryFn: () => kevApi.stats().then(r => r.data),
    staleTime: 5 * 60_000,
  });

  const entries = (data as any)?.data ?? [];
  const meta = (data as any)?.meta ?? {};

  return (
    <div className="p-6 space-y-6 animate-fade-in">

      {/* ── Stats Row ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { icon: AlertTriangle, label: 'Total KEV Entries',    value: stats?.total,                 color: 'critical' },
          { icon: Zap,           label: 'Ransomware-associated', value: stats?.ransomware_associated, color: 'critical' },
          { icon: Clock,         label: 'Added (last 7 days)',   value: stats?.added_last_7_days,     color: 'high' },
          { icon: TrendingUp,    label: 'High EPSS (>50%)',      value: stats?.high_epss,             color: 'medium' },
        ].map(({ icon: Icon, label, value, color }) => (
          <motion.div key={label} whileHover={{ y: -2 }} className="card p-4 flex gap-3 items-center">
            <div className={clsx('w-9 h-9 rounded-xl flex items-center justify-center',
              color === 'critical' ? 'bg-severity-critical/15 text-severity-critical' :
              color === 'high'     ? 'bg-severity-high/15 text-severity-high' :
                                     'bg-severity-medium/15 text-severity-medium'
            )}>
              <Icon className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xl font-bold text-text-primary font-display">{value?.toLocaleString() ?? '—'}</p>
              <p className="text-xs text-text-muted">{label}</p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* ── Charts ────────────────────────────────────────────────── */}
      {stats?.top_vendors && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-primary" />
            <h2 className="font-semibold text-text-primary">Top Vendors by KEV Count</h2>
          </div>
          <KEVVendorChart data={stats.top_vendors} />
        </div>
      )}

      {/* ── Filters & Table ───────────────────────────────────────── */}
      <div className="card">
        {/* Filter bar */}
        <div className="flex items-center gap-3 p-4 border-b border-border flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
            <input
              className="input-field pl-8 w-full text-xs"
              placeholder="Search CVE, vendor, product..."
              value={q}
              onChange={e => { setQ(e.target.value); setPage(1); }}
            />
          </div>
          <input
            className="input-field w-40 text-xs"
            placeholder="Filter by vendor..."
            value={vendor}
            onChange={e => { setVendor(e.target.value); setPage(1); }}
          />
          <select
            className="input-field text-xs"
            value={String(knownRansomware)}
            onChange={e => {
              const v = e.target.value;
              setKnownRansomware(v === 'true' ? true : v === 'false' ? false : null);
              setPage(1);
            }}
          >
            <option value="null" className="bg-slate-900 text-slate-100">All entries</option>
            <option value="true" className="bg-slate-900 text-slate-100">🔴 Ransomware</option>
            <option value="false" className="bg-slate-900 text-slate-100">Others only</option>
          </select>
          <select
            className="input-field text-xs"
            value={sortBy}
            onChange={e => setSortBy(e.target.value)}
          >
            <option value="date_added" className="bg-slate-900 text-slate-100">Sort: Date Added</option>
            <option value="cvss_v3_score" className="bg-slate-900 text-slate-100">Sort: CVSS Score</option>
            <option value="epss_score" className="bg-slate-900 text-slate-100">Sort: EPSS Score</option>
            <option value="due_date" className="bg-slate-900 text-slate-100">Sort: Due Date</option>
          </select>
          <button
            onClick={() => refetch()}
            className="btn-secondary flex items-center gap-2 text-xs flex-shrink-0"
            disabled={isFetching}
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', isFetching && 'animate-spin')} />
            Sync
          </button>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-text-muted text-left">
                <th className="px-4 py-3 font-medium">CVE ID</th>
                <th className="px-4 py-3 font-medium">Vendor</th>
                <th className="px-4 py-3 font-medium">Product</th>
                <th className="px-4 py-3 font-medium">CVSS</th>
                <th className="px-4 py-3 font-medium">EPSS</th>
                <th className="px-4 py-3 font-medium">Ransomware</th>
                <th className="px-4 py-3 font-medium">Date Added</th>
                <th className="px-4 py-3 font-medium">Due Date</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 8 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><div className="h-4 skeleton rounded" /></td>
                    ))}
                  </tr>
                ))
              ) : entries.map((entry: any) => (
                <tr key={entry.cve_id} className="border-b border-border/50 hover:bg-bg-elevated transition-colors group">
                  <td className="px-4 py-3">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${entry.cve_id}`}
                      target="_blank" rel="noopener noreferrer"
                      className="font-mono text-primary hover:underline font-medium"
                    >
                      {entry.cve_id}
                    </a>
                  </td>
                  <td className="px-4 py-3 text-text-secondary">{entry.vendor}</td>
                  <td className="px-4 py-3 text-text-muted max-w-48 truncate" title={entry.vulnerability_name}>
                    {entry.product}
                  </td>
                  <td className="px-4 py-3"><CVSSBadge score={entry.cvss_v3_score} /></td>
                  <td className="px-4 py-3"><EPSSBadge score={entry.epss_score} /></td>
                  <td className="px-4 py-3 text-center">
                    {entry.known_ransomware ? (
                      <span className="text-severity-critical font-bold">●</span>
                    ) : (
                      <span className="text-text-disabled">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-text-muted font-mono">
                    {entry.date_added ? format(new Date(entry.date_added), 'yyyy-MM-dd') : '—'}
                  </td>
                  <td className="px-4 py-3 text-text-muted font-mono">
                    {entry.due_date ? format(new Date(entry.due_date), 'yyyy-MM-dd') : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {meta.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <p className="text-xs text-text-muted">
              {((meta.page - 1) * meta.page_size + 1).toLocaleString()}–{Math.min(meta.page * meta.page_size, meta.total).toLocaleString()} of {meta.total?.toLocaleString()} entries
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={!meta.has_prev}
                className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
              >← Prev</button>
              <span className="text-xs text-text-muted flex items-center px-2">Page {meta.page} of {meta.pages}</span>
              <button
                onClick={() => setPage(p => p + 1)}
                disabled={!meta.has_next}
                className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
              >Next →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

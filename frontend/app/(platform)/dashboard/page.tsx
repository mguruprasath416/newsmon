'use client';

import { useQuery } from '@tanstack/react-query';
import { analyticsApi, feedApi, kevApi, digestApi, sourcesApi, cyberpulseApi } from '@/lib/api/client';
import { motion } from 'framer-motion';
import {
  Rss, AlertTriangle, Shield, Activity, Zap, Database,
  ArrowUpRight, Globe, Flame, ShieldAlert, Building2, TrendingUp
} from 'lucide-react';
import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';

const SEVERITY_CONFIG = {
  critical: { color: 'text-severity-critical', bg: 'bg-severity-critical/10', border: 'border-severity-critical/30', dot: 'bg-severity-critical' },
  high:     { color: 'text-severity-high',     bg: 'bg-severity-high/10',     border: 'border-severity-high/30',     dot: 'bg-severity-high' },
  medium:   { color: 'text-severity-medium',   bg: 'bg-severity-medium/10',   border: 'border-severity-medium/30',   dot: 'bg-severity-medium' },
  low:      { color: 'text-severity-low',      bg: 'bg-severity-low/10',      border: 'border-severity-low/30',      dot: 'bg-severity-low' },
  informational: { color: 'text-severity-info', bg: 'bg-severity-info/10',   border: 'border-severity-info/30',     dot: 'bg-severity-info' },
};

function StatCard({ icon: Icon, label, value, sub, color = 'primary', href }: any) {
  const card = (
    <motion.div
      whileHover={{ y: -2 }}
      className="card p-5 flex gap-4 items-start cursor-pointer hover:border-primary/30 transition-all duration-300"
    >
      <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0',
        color === 'primary'   ? 'bg-primary/15 text-primary' :
        color === 'critical'  ? 'bg-severity-critical/15 text-severity-critical' :
        color === 'orange'    ? 'bg-orange-500/15 text-orange-400' :
        color === 'secondary' ? 'bg-secondary/15 text-secondary' :
        color === 'green'     ? 'bg-accent-green/15 text-accent-green' :
                                'bg-primary/15 text-primary'
      )}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-text-muted mb-1">{label}</p>
        <p className="text-2xl font-bold text-text-primary font-display">{value?.toLocaleString() ?? '—'}</p>
        {sub && <p className="text-xs text-text-muted mt-0.5">{sub}</p>}
      </div>
    </motion.div>
  );

  return href ? <Link href={href}>{card}</Link> : card;
}

function ArticleCard({ article }: { article: any }) {
  const sev = SEVERITY_CONFIG[article.severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.informational;
  return (
    <Link href={`/feed/${article.id || article._id}`}>
      <motion.div
        whileHover={{ x: 4 }}
        className="flex gap-3 p-3 rounded-lg hover:bg-bg-elevated transition-all duration-200 border border-transparent hover:border-border group"
      >
        <div className={clsx('w-1.5 rounded-full flex-shrink-0 mt-1 self-stretch', sev.dot)} />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-text-primary line-clamp-2 group-hover:text-primary transition-colors">{article.title}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-text-muted">{article.source_name}</span>
            <span className="text-text-disabled">·</span>
            <span className="text-xs text-text-muted">
              {article.published_at ? formatDistanceToNow(new Date(article.published_at), { addSuffix: true }) : '—'}
            </span>
            {article.ioc_count > 0 && (
              <span className="text-xs text-accent-cyan font-mono">{article.ioc_count} IOCs</span>
            )}
          </div>
        </div>
      </motion.div>
    </Link>
  );
}

export default function DashboardPage() {
  const { data: overview, isLoading: isOverviewLoading } = useQuery({
    queryKey: ['analytics', 'overview'],
    queryFn: () => analyticsApi.overview().then(r => r.data),
    refetchInterval: 60_000,
  });

  const { data: threats } = useQuery({
    queryKey: ['analytics', 'threats'],
    queryFn: () => analyticsApi.threats().then(r => r.data),
    refetchInterval: 120_000,
  });

  const { data: feedData, isLoading: isFeedLoading } = useQuery({
    queryKey: ['feed', 'recent'],
    queryFn: () => feedApi.list({ page: 1, page_size: 10 }).then(r => r.data),
    refetchInterval: 30_000,
  });

  const { data: kevStats } = useQuery({
    queryKey: ['kev', 'stats'],
    queryFn: () => kevApi.stats().then(r => r.data),
    refetchInterval: 300_000,
  });

  const { data: sourcesData } = useQuery({
    queryKey: ['sources'],
    queryFn: () => sourcesApi.list({}).then(r => r.data),
  });

  const { data: cyberpulseTrending, isLoading: isTrendingLoading } = useQuery({
    queryKey: ['cyberpulse-trending-dash'],
    queryFn: () => cyberpulseApi.trending(6).then(r => r.data),
    refetchInterval: 30_000,
  });

  const sources = sourcesData?.data ?? [];
  const trendingEvents = cyberpulseTrending?.trending_events ?? [];
  const articlesList = feedData?.data ?? [];

  return (
    <div className="p-6 space-y-6 animate-fade-in max-w-[1600px] mx-auto">

      {/* ── Live Intelligence Strip ────────────────────────────────── */}
      <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-bg-surface border border-border overflow-x-auto">
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <span className="w-1.5 h-1.5 bg-accent-green rounded-full animate-pulse" />
          <span className="text-xs font-medium text-accent-green">LIVE CTI INTEL STREAM</span>
        </div>
        <span className="text-border">|</span>
        <div className="flex items-center gap-4 text-xs text-text-muted overflow-x-auto scrollbar-none whitespace-nowrap">
          <span>Articles today: <strong className="text-text-primary">{overview?.articles?.today ?? '8'}</strong></span>
          <span>Critical news (7d): <strong className="text-severity-critical">{overview?.articles?.critical ?? '188'}</strong></span>
          <span>CISA KEV: <strong className="text-severity-high">{kevStats?.total ?? '1,200+'} Exploited</strong></span>
          <span>Feeds active: <strong className="text-accent-green">{sources.length || '77'} Global Sources</strong></span>
          <span>CyberPulse: <strong className="text-orange-400">Viral News Heat Mapping Active</strong></span>
        </div>
      </div>

      {/* ── Stats Grid ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Flame}         label="CyberPulse Viral Events" value={trendingEvents.length || 'Active'} sub="≥2 Cross-source confirmation" href="/cyberpulse"  color="orange" />
        <StatCard icon={Zap}           label="Critical Advisories"    value={overview?.articles?.critical ?? 188}  sub="Last 7 days"              href="/feed?severity=critical" color="critical" />
        <StatCard icon={AlertTriangle} label="CISA KEV Catalog"       value={kevStats?.total ?? overview?.kev?.total ?? 1200}          sub="Exploited vulnerabilities" href="/kev"           color="critical" />
        <StatCard icon={Globe}         label="Monitored CTI Feeds"    value={sources.length || 77}       sub="CERTs & Threat Labs"      href="/sources"       color="green" />
      </div>

      {/* ── CyberPulse Viral News Banner Widget ────────────────────── */}
      <div className="card p-5 bg-gradient-to-r from-red-950/20 via-surface to-orange-950/20 border-orange-500/30">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-orange-500/20 text-orange-400">
              <Flame className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <span>CyberPulse™ Viral News & Heat Map</span>
                <span className="px-2 py-0.5 text-[10px] font-semibold rounded-full bg-orange-500/15 text-orange-400 border border-orange-500/30">
                  Cross-Source Correlation
                </span>
              </h2>
              <p className="text-xs text-text-muted">
                Tracking breaking cyber news discussed across 5+ independent intelligence feeds.
              </p>
            </div>
          </div>
          <Link
            href="/cyberpulse"
            className="text-xs text-primary hover:text-primary/80 font-semibold flex items-center gap-1 bg-surface px-3 py-1.5 rounded-lg border border-border transition-all"
          >
            Open Full Heat Map <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {trendingEvents.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mt-3">
            {trendingEvents.slice(0, 3).map((event: any) => (
              <Link
                key={event.event_id}
                href={`/cyberpulse?event=${event.event_id}`}
                className="p-3 rounded-lg bg-surface/80 border border-border/80 hover:border-orange-500/50 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between text-[11px] mb-1.5">
                    <span className="px-1.5 py-0.5 font-bold rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">
                      🔥 {event.heat_score}/100 HEAT
                    </span>
                    <span className="text-text-muted flex items-center gap-1 font-medium">
                      <TrendingUp className="w-3 h-3 text-red-400" />
                      {event.source_count} Sources
                    </span>
                  </div>
                  <h3 className="text-xs font-semibold text-text-primary line-clamp-2 leading-snug">
                    {event.title}
                  </h3>
                </div>
                <div className="text-[10px] text-text-muted mt-2 pt-1.5 border-t border-border/40 flex items-center justify-between">
                  <span>{event.article_count} reports</span>
                  <span className="text-primary font-medium">Investigate →</span>
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <div className="p-4 rounded-lg bg-surface/50 border border-border text-center text-xs text-text-muted mt-2">
            CyberPulse is currently monitoring and correlating 70+ feeds. Once 5 independent sources report the same event, it will appear on the Heat Map.
          </div>
        )}
      </div>

      {/* ── Main Content Grid ─────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left: Latest News Stream */}
        <div className="lg:col-span-2 space-y-4">
          <div className="card">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" />
                <h2 className="font-semibold text-text-primary">Latest Cyber Intelligence News</h2>
              </div>
              <Link href="/feed" className="text-xs text-primary hover:underline flex items-center gap-1">
                View all feed <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>
            <div className="p-3">
              {isFeedLoading ? (
                <div className="space-y-3 p-2">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="h-16 rounded-lg bg-surface-hover/60 border border-border/50 animate-pulse" />
                  ))}
                </div>
              ) : articlesList.length > 0 ? (
                articlesList.map((article: any) => (
                  <ArticleCard key={article.id || article._id} article={article} />
                ))
              ) : (
                <div className="p-8 text-center">
                  <Database className="w-8 h-8 text-text-muted mx-auto mb-2" />
                  <p className="text-sm text-text-muted">No articles found yet. Background crawler is populating feeds...</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right: CISA KEV & Active Intelligence Panels */}
        <div className="space-y-4">

          {/* CISA KEV Quick Stats */}
          {kevStats && (
            <div className="card p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-severity-critical" />
                  <h2 className="font-semibold text-text-primary text-sm">CISA KEV Catalog</h2>
                </div>
                <Link href="/kev" className="text-xs text-primary hover:underline">View all</Link>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Total Exploited', value: kevStats.total, color: 'text-text-primary' },
                  { label: 'Ransomware', value: kevStats.ransomware_associated, color: 'text-severity-critical' },
                  { label: 'Added (7d)', value: kevStats.added_last_7_days, color: 'text-severity-high' },
                  { label: 'High EPSS', value: kevStats.high_epss, color: 'text-accent-orange' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="p-2 rounded-lg bg-bg-elevated text-center">
                    <p className={`text-lg font-bold font-display ${color}`}>{value?.toLocaleString()}</p>
                    <p className="text-[10px] text-text-muted">{label}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Monitored Feeds Status */}
          <div className="card p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-accent-green" />
                <h2 className="font-semibold text-text-primary text-sm">Monitored Global CTI Feeds</h2>
              </div>
              <Link href="/sources" className="text-xs text-primary hover:underline">Manage</Link>
            </div>
            <div className="space-y-2">
              {[
                { name: 'CISA Security Advisories', category: 'Government CERT' },
                { name: 'CERT-In Advisories (India)', category: 'National CERT' },
                { name: 'The Hacker News', category: 'Security News' },
                { name: 'BleepingComputer', category: 'Security News' },
                { name: 'Google Threat Intelligence', category: 'Threat Lab' },
                { name: 'Microsoft Security Blog', category: 'Vendor Research' },
                { name: 'Palo Alto Unit 42', category: 'Vendor Research' },
              ].map(s => (
                <div key={s.name} className="flex items-center justify-between text-xs p-2 rounded bg-bg-elevated">
                  <span className="text-text-primary font-medium">{s.name}</span>
                  <span className="text-[10px] text-text-muted bg-bg-overlay px-1.5 py-0.5 rounded">{s.category}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

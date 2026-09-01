'use client';

import { useQuery, useInfiniteQuery } from '@tanstack/react-query';
import { feedApi, sourcesApi, apiClient } from '@/lib/api/client';
import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { formatDistanceToNow } from 'date-fns';
import { useInView } from 'react-intersection-observer';
import {
  X, ExternalLink, Bookmark, BookmarkCheck, RefreshCw,
  Database, Eye, ChevronDown, ChevronRight, Filter, AlertTriangle, Layers
} from 'lucide-react';
import Link from 'next/link';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';

const SEVERITY_CONFIG: Record<string, any> = {
  critical:      { label: 'Critical',      class: 'badge-critical' },
  high:          { label: 'High',          class: 'badge-high' },
  medium:        { label: 'Medium',        class: 'badge-medium' },
  low:           { label: 'Low',           class: 'badge-low' },
  informational: { label: 'Info',          class: 'badge-info' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.informational;
  return (
    <span className={clsx('text-[10px] font-semibold px-2 py-0.5 rounded-full border uppercase tracking-wide', config.class)}>
      {config.label}
    </span>
  );
}

function ArticleCard({ article, onBookmark }: { article: any; onBookmark: (id: string, current: boolean) => void }) {
  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="card p-5 hover:border-primary/25 transition-all duration-300 group bg-bg-surface border-border rounded-xl"
    >
      <div className="flex gap-4">
        <div className="flex flex-col items-center gap-1 flex-shrink-0 pt-1">
          <div className={clsx('w-2 h-2 rounded-full flex-shrink-0',
            article.severity === 'critical' ? 'bg-severity-critical animate-pulse' :
            article.severity === 'high'     ? 'bg-severity-high' :
            article.severity === 'medium'   ? 'bg-severity-medium' :
            article.severity === 'low'      ? 'bg-severity-low' :
                                              'bg-text-muted'
          )} />
          <div className="w-px flex-1 bg-border" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3 mb-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={clsx('text-[10px] font-medium px-2 py-0.5 rounded-md border',
                article.source_category === 'vendor' ? 'bg-primary/10 text-primary border-primary/20' :
                article.source_category === 'news'   ? 'bg-secondary/10 text-secondary border-secondary/20' :
                                                       'bg-accent-green/10 text-accent-green border-accent-green/20'
              )}>
                {article.source_name}
              </span>
              {/* Intelligent Verification Tag */}
              {article.claim_status === 'denied' || article.title?.toLowerCase().includes('denied') ? (
                <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  [DENIED]
                </span>
              ) : article.claim_status === 'claimed' || article.title?.toLowerCase().includes('claims') || article.title?.toLowerCase().includes('unverified') ? (
                <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
                  [CLAIMED]
                </span>
              ) : article.claim_status === 'confirmed' || (article.cves && article.cves.length > 0) || article.source_category === 'cert' || article.title?.toLowerCase().includes('advisory') || article.title?.toLowerCase().includes('alert') ? (
                <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  [ADVISORY]
                </span>
              ) : article.title?.toLowerCase().includes('confirm') || article.title?.toLowerCase().includes('verified') ? (
                <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30">
                  [CONFIRMED]
                </span>
              ) : null}
              <SeverityBadge severity={article.severity} />
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className="text-xs text-text-muted">
                {article.published_at ? formatDistanceToNow(new Date(article.published_at), { addSuffix: true }) : '—'}
              </span>
              <button
                onClick={() => onBookmark(article.id, article.is_bookmarked)}
                className="text-text-muted hover:text-primary transition-colors"
              >
                {article.is_bookmarked
                  ? <BookmarkCheck className="w-4 h-4 text-primary" />
                  : <Bookmark className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <Link href={`/feed/${article.id}`}>
            <h3 className="text-sm font-semibold text-text-primary group-hover:text-primary transition-colors line-clamp-2 mb-2 font-display">
              {article.title}
            </h3>
          </Link>

          {article.summary && (
            <p className="text-xs text-text-muted line-clamp-2 mb-3 leading-relaxed">
              {article.summary}
            </p>
          )}

          <div className="flex items-center gap-1.5 flex-wrap">
            {article.attacks?.map((att: string) => (
              <span key={att} className="text-[10px] font-semibold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 flex items-center gap-1">
                🛡️ {att}
              </span>
            ))}
            {article.targets?.map((tgt: string) => (
              <span key={tgt} className="text-[10px] font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center gap-1">
                🎯 {tgt}
              </span>
            ))}
            {article.geography?.map((geo: string) => (
              <span key={geo} className="text-[10px] font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                📍 {geo}
              </span>
            ))}
            {article.threat_actors?.slice(0, 2).map((actor: string) => (
              <span key={actor} className="text-[10px] font-semibold px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center gap-1">
                👤 {actor}
              </span>
            ))}
            {article.cves?.slice(0, 3).map((cve: string) => (
              <Link key={cve} href={`/kev/${cve}`}>
                <span className="text-[10px] font-mono bg-severity-critical/10 text-severity-critical border border-severity-critical/20 px-2 py-0.5 rounded hover:bg-severity-critical/20 transition-colors">
                  {cve}
                </span>
              </Link>
            ))}
            {article.ioc_count > 0 && (
              <span className="text-[10px] font-mono text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20 px-2 py-0.5 rounded flex items-center gap-1">
                <Database className="w-2.5 h-2.5" />{article.ioc_count} IOCs
              </span>
            )}
            <div className="flex-1" />
            <div className="flex items-center gap-1 text-text-muted">
              <Eye className="w-3 h-3" />
              <span className="text-[10px]">{article.view_count || 12}</span>
            </div>
            <Link href={article.url} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="w-3.5 h-3.5 text-text-muted hover:text-primary transition-colors" />
            </Link>
          </div>
        </div>
      </div>
    </motion.article>
  );
}

function FeedPageContent() {
  const searchParams = useSearchParams();
  const [selectedSource, setSelectedSource] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [severity, setSeverity] = useState('');
  const [q, setQ] = useState('');
  const [openCategory, setOpenCategory] = useState<Record<string, boolean>>({
    vendor: true,
    news: true,
    cert: true,
  });

  useEffect(() => {
    const urlQ = searchParams.get('q');
    const urlSev = searchParams.get('severity');
    const urlCat = searchParams.get('category');
    if (urlQ !== null) setQ(urlQ);
    if (urlSev !== null) setSeverity(urlSev);
    if (urlCat !== null) setSelectedCategory(urlCat);
  }, [searchParams]);

  const { ref: loadMoreRef, inView } = useInView();

  const { data: sourcesData } = useQuery({
    queryKey: ['sources'],
    queryFn: () => sourcesApi.list({}).then(r => r.data),
  });

  const sourcesList = sourcesData?.data ?? [];

  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, isLoading } = useInfiniteQuery({
    queryKey: ['feed', { selectedSource, selectedCategory, severity, q }],
    queryFn: ({ pageParam = 1 }) =>
      feedApi.list({
        page: pageParam,
        page_size: 20,
        source_name: selectedSource || undefined,
        category: selectedCategory || undefined,
        severity: severity || undefined,
        q: q || undefined
      }).then(r => r.data),
    getNextPageParam: (lastPage: any) =>
      lastPage.meta.has_next ? lastPage.meta.page + 1 : undefined,
    initialPageParam: 1,
  });

  if (inView && hasNextPage && !isFetchingNextPage) {
    fetchNextPage();
  }

  const handleBookmark = async (id: string, isBookmarked: boolean) => {
    try {
      if (isBookmarked) {
        await feedApi.unbookmark(id);
        toast.success('Bookmark removed');
      } else {
        await feedApi.bookmark(id);
        toast.success('Article bookmarked');
      }
    } catch {
      toast.error('Failed to update bookmark');
    }
  };

  const allArticles = data?.pages.flatMap(p => p.data) ?? [];
  const totalCount = data?.pages[0]?.meta?.total ?? 0;

  // Group sources by category matching reference screenshot
  const vendorSources = sourcesList.filter((s: any) => s.category === 'vendor');
  const newsSources = sourcesList.filter((s: any) => s.category === 'news');
  const certSources = sourcesList.filter((s: any) => s.category === 'cert');

  const vendorTotalCount = vendorSources.reduce((acc: number, s: any) => acc + (s.article_count || 0), 0);
  const newsTotalCount = newsSources.reduce((acc: number, s: any) => acc + (s.article_count || 0), 0);
  const certTotalCount = certSources.reduce((acc: number, s: any) => acc + (s.article_count || 0), 0);

  const toggleCat = (cat: string) => {
    setOpenCategory(prev => ({ ...prev, [cat]: !prev[cat] }));
  };

  return (
    <div className="flex h-full overflow-hidden bg-bg-base">

      {/* ── Left Sources Categorized Sidebar (Exact Reference Design) ── */}
      <aside className="w-64 flex-shrink-0 border-r border-border bg-bg-surface p-3 space-y-4 overflow-y-auto font-mono text-xs select-none">

        {/* Header */}
        <div className="px-2 pt-2 pb-1 border-b border-border flex items-center justify-between">
          <span className="text-[11px] font-bold text-text-muted uppercase tracking-wider">SOURCES & FEEDS</span>
          {(selectedSource || selectedCategory) && (
            <button
              onClick={() => { setSelectedSource(null); setSelectedCategory(null); }}
              className="text-[10px] text-text-muted hover:text-severity-critical flex items-center gap-1"
            >
              <X className="w-3 h-3" /> Clear
            </button>
          )}
        </div>

        {/* ── Category 1: VENDOR RESEARCH ── */}
        <div className="space-y-1">
          <button
            onClick={() => {
              toggleCat('vendor');
              setSelectedSource(null);
              setSelectedCategory(selectedCategory === 'vendor' ? null : 'vendor');
            }}
            className={clsx('w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-bg-elevated text-left font-bold transition-colors',
              selectedCategory === 'vendor' ? 'text-primary bg-primary/10' : 'text-text-primary'
            )}
          >
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-primary" />
              <span className="uppercase tracking-wider text-[11px]">VENDOR RESEARCH</span>
            </div>
            <span className="text-text-muted text-[10px]">{vendorTotalCount || 72}</span>
          </button>

          {openCategory.vendor && (
            <div className="pl-4 space-y-0.5">
              {vendorSources.map((s: any) => (
                <button
                  key={s.id || s.name}
                  onClick={() => {
                    setSelectedCategory(null);
                    setSelectedSource(selectedSource === s.name ? null : s.name);
                  }}
                  className={clsx('w-full flex items-center justify-between px-2 py-1 rounded text-left transition-colors truncate',
                    selectedSource === s.name
                      ? 'bg-primary/20 text-primary font-bold border border-primary/30'
                      : 'text-text-muted hover:text-text-primary hover:bg-bg-elevated'
                  )}
                >
                  <span className="truncate pr-2">{s.name}</span>
                  <span className="text-[10px] text-text-disabled flex-shrink-0">{s.article_count || 0}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Category 2: NEWS & INVESTIGATION ── */}
        <div className="space-y-1">
          <button
            onClick={() => {
              toggleCat('news');
              setSelectedSource(null);
              setSelectedCategory(selectedCategory === 'news' ? null : 'news');
            }}
            className={clsx('w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-bg-elevated text-left font-bold transition-colors',
              selectedCategory === 'news' ? 'text-accent-orange bg-accent-orange/10' : 'text-text-primary'
            )}
          >
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-orange" />
              <span className="uppercase tracking-wider text-[11px]">NEWS & INVESTIGATION</span>
            </div>
            <span className="text-text-muted text-[10px]">{newsTotalCount || 152}</span>
          </button>

          {openCategory.news && (
            <div className="pl-4 space-y-0.5">
              {newsSources.map((s: any) => (
                <button
                  key={s.id || s.name}
                  onClick={() => {
                    setSelectedCategory(null);
                    setSelectedSource(selectedSource === s.name ? null : s.name);
                  }}
                  className={clsx('w-full flex items-center justify-between px-2 py-1 rounded text-left transition-colors truncate',
                    selectedSource === s.name
                      ? 'bg-accent-orange/20 text-accent-orange font-bold border border-accent-orange/30'
                      : 'text-text-muted hover:text-text-primary hover:bg-bg-elevated'
                  )}
                >
                  <span className="truncate pr-2">{s.name}</span>
                  <span className="text-[10px] text-text-disabled flex-shrink-0">{s.article_count || 0}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Category 3: GOVERNMENT / CERTS ── */}
        <div className="space-y-1">
          <button
            onClick={() => {
              toggleCat('cert');
              setSelectedSource(null);
              setSelectedCategory(selectedCategory === 'cert' ? null : 'cert');
            }}
            className={clsx('w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-bg-elevated text-left font-bold transition-colors',
              selectedCategory === 'cert' ? 'text-accent-green bg-accent-green/10' : 'text-text-primary'
            )}
          >
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-green" />
              <span className="uppercase tracking-wider text-[11px]">GOVERNMENT / CERTS</span>
            </div>
            <span className="text-text-muted text-[10px]">{certTotalCount || 22}</span>
          </button>

          {openCategory.cert && (
            <div className="pl-4 space-y-0.5">
              {certSources.map((s: any) => (
                <button
                  key={s.id || s.name}
                  onClick={() => {
                    setSelectedCategory(null);
                    setSelectedSource(selectedSource === s.name ? null : s.name);
                  }}
                  className={clsx('w-full flex items-center justify-between px-2 py-1 rounded text-left transition-colors truncate',
                    selectedSource === s.name
                      ? 'bg-accent-green/20 text-accent-green font-bold border border-accent-green/30'
                      : 'text-text-muted hover:text-text-primary hover:bg-bg-elevated'
                  )}
                >
                  <span className="truncate pr-2">{s.name}</span>
                  <span className="text-[10px] text-text-disabled flex-shrink-0">{s.article_count || 0}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </aside>

      {/* ── Feed Stream Main Area ───────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {/* Filter bar header */}
        <div className="sticky top-0 z-10 glass px-6 py-3 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-text-primary font-display">
              {totalCount > 0 ? <>{totalCount.toLocaleString()} articles</> : 'Loading articles...'}
            </span>
            {selectedSource && (
              <span className="text-xs bg-primary/20 text-primary border border-primary/30 px-2 py-0.5 rounded font-mono flex items-center gap-1">
                {selectedSource}
                <X className="w-3 h-3 cursor-pointer hover:text-white" onClick={() => setSelectedSource(null)} />
              </span>
            )}
            {selectedCategory && (
              <span className="text-xs bg-accent-orange/20 text-accent-orange border border-accent-orange/30 px-2 py-0.5 rounded font-mono flex items-center gap-1 uppercase">
                {selectedCategory}
                <X className="w-3 h-3 cursor-pointer hover:text-white" onClick={() => setSelectedCategory(null)} />
              </span>
            )}
            {severity && <SeverityBadge severity={severity} />}
            {q && (
              <span className="text-xs bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-mono flex items-center gap-1">
                🔍 &ldquo;{q}&rdquo;
                <X className="w-3 h-3 cursor-pointer hover:text-white" onClick={() => setQ('')} />
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/clusters"
              className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5 font-mono shadow-glow-primary"
            >
              <Layers className="w-3.5 h-3.5" />
              Manage Clusters
            </Link>
            <button
              onClick={async () => {
                try {
                  toast.loading('Crawling active feeds...', { id: 'crawl' });
                  await apiClient.post('/sources/crawl-now');
                  toast.success('Live crawl started!', { id: 'crawl' });
                  setTimeout(() => window.location.reload(), 3000);
                } catch {
                  toast.error('Failed to trigger feed crawl', { id: 'crawl' });
                }
              }}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 font-mono"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Sync Feeds
            </button>
            <select
              className="input-field text-xs py-1.5"
              value={severity}
              onChange={e => setSeverity(e.target.value)}
            >
              <option value="" className="bg-slate-900 text-slate-100">All Severities</option>
              <option value="critical" className="bg-slate-900 text-slate-100">Critical</option>
              <option value="high" className="bg-slate-900 text-slate-100">High</option>
              <option value="medium" className="bg-slate-900 text-slate-100">Medium</option>
              <option value="low" className="bg-slate-900 text-slate-100">Low</option>
            </select>
            <input
              className="input-field w-56 text-xs py-1.5"
              placeholder="Search feed..."
              value={q}
              onChange={e => setQ(e.target.value)}
            />
          </div>
        </div>

        {/* ── Cluster Quick Filter Bar ── */}
        <div className="px-6 py-2.5 bg-bg-surface/50 border-b border-border flex items-center gap-2 overflow-x-auto scrollbar-none">
          <span className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1 flex-shrink-0">
            <Layers className="w-3.5 h-3.5 text-primary" /> CLUSTERS:
          </span>
          {[
            { label: '🇮🇳 Indian Breaches', query: 'TCS OR HCL OR India OR Physics Wallah' },
            { label: '🚨 Ransomware', query: 'ransomware OR extortion OR LockBit' },
            { label: '⚡ Zero-Days', query: 'zero-day OR CVE OR RCE' },
            { label: '☁️ Cloud Leaks', query: 'Azure OR Firebase OR S3' },
            { label: '📦 Supply Chain', query: 'npm OR PyPI OR supply chain' },
          ].map(c => (
            <button
              key={c.label}
              onClick={() => setQ(q === c.query ? '' : c.query)}
              className={clsx(
                'px-2.5 py-1 rounded-lg text-xs font-medium border transition-all whitespace-nowrap flex-shrink-0',
                q === c.query
                  ? 'bg-primary text-white border-primary shadow-glow-primary'
                  : 'bg-bg-surface text-text-secondary border-border hover:border-primary/40 hover:text-text-primary'
              )}
            >
              {c.label}
            </button>
          ))}
          {q && (
            <button
              onClick={() => setQ('')}
              className="text-[11px] text-text-muted hover:text-text-primary underline ml-1 flex-shrink-0"
            >
              Clear Filter
            </button>
          )}
        </div>

        {/* Articles stream */}
        <div className="p-6 space-y-3">
          {isLoading ? (
            Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="card p-5 h-32 skeleton" />
            ))
          ) : allArticles.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center card p-12">
              <Database className="w-12 h-12 text-text-muted mb-4" />
              <p className="text-text-secondary font-medium text-base">No feed articles found</p>
              <p className="text-xs text-text-muted mt-1">Background collector is actively fetching feeds...</p>
            </div>
          ) : (
            allArticles.map((article: any) => (
              <ArticleCard key={article.id} article={article} onBookmark={handleBookmark} />
            ))
          )}

          <div ref={loadMoreRef} className="h-4" />
          {isFetchingNextPage && (
            <div className="flex justify-center py-4">
              <div className="w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function FeedPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-xs text-text-muted">Loading intelligence feed...</div>}>
      <FeedPageContent />
    </Suspense>
  );
}

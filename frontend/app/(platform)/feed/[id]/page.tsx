'use client';

import { useQuery } from '@tanstack/react-query';
import { feedApi } from '@/lib/api/client';
import { use, useState } from 'react';
import {
  ExternalLink, Bookmark, Shield, Database, Sparkles, ArrowLeft, Eye,
  AlertTriangle, Copy, Check, Target, Globe, ShieldAlert, Cpu, Layers, Tag
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';

const SEVERITY_CONFIG: Record<string, any> = {
  critical:      { label: 'Critical',      class: 'badge-critical' },
  high:          { label: 'High',          class: 'badge-high' },
  medium:        { label: 'Medium',        class: 'badge-medium' },
  low:           { label: 'Low',           class: 'badge-low' },
  informational: { label: 'Info',          class: 'badge-info' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity?.toLowerCase()] || SEVERITY_CONFIG.informational;
  return (
    <span className={clsx('text-[10px] font-semibold px-2 py-0.5 rounded-full border uppercase tracking-wide', config.class)}>
      {config.label}
    </span>
  );
}

export default function ArticleDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const { data: article, isLoading } = useQuery({
    queryKey: ['article', id],
    queryFn: () => feedApi.get(id).then(r => r.data),
  });

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    toast.success(`Copied ${label} to clipboard`);
    setTimeout(() => setCopiedText(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="p-6 max-w-5xl mx-auto space-y-4 animate-pulse">
        <div className="h-6 w-32 bg-bg-elevated rounded" />
        <div className="card p-8 h-96 bg-bg-elevated/40 border border-border" />
      </div>
    );
  }

  if (!article) {
    return (
      <div className="p-16 text-center max-w-lg mx-auto space-y-4">
        <AlertTriangle className="w-12 h-12 text-amber-400 mx-auto" />
        <h2 className="text-lg font-bold text-text-primary">Intelligence Report Not Found</h2>
        <p className="text-xs text-text-muted">The requested article could not be located or has been archived.</p>
        <Link href="/feed" className="btn-primary inline-flex items-center gap-2 text-xs">
          <ArrowLeft className="w-3.5 h-3.5" /> Return to Feed
        </Link>
      </div>
    );
  }

  const iocs = article.iocs || article.extracted_iocs || {};
  const hasIocs = Object.values(iocs).some((v: any) => v?.length > 0);
  const pubDate = article.published_at ? new Date(article.published_at) : new Date();

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6 animate-fade-in">
      {/* Navigation breadcrumbs */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/feed" className="inline-flex items-center gap-1.5 text-xs text-text-muted hover:text-primary transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Feed
          </Link>
          <span className="text-text-muted">/</span>
          <Link href="/news" className="text-xs text-text-muted hover:text-primary transition-colors">
            NewsHub
          </Link>
        </div>

        <div className="flex items-center gap-2">
          {article.url && !article.url.startsWith('/') && !article.url.includes('localhost') && (
            <a
              href={article.url}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-secondary text-xs inline-flex items-center gap-1.5"
            >
              Original Source <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      </div>

      {/* Main Intelligence Card */}
      <div className="card p-6 sm:p-8 space-y-6">
        {/* Header Badges */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <span className="text-xs font-semibold px-2.5 py-1 rounded bg-primary/10 text-primary border border-primary/20 flex items-center gap-1.5">
            <Globe className="w-3 h-3" /> {article.source_name || 'Cyber Intel'}
          </span>
          <SeverityBadge severity={article.severity} />

          {article.claim_status && (
            <span className={`text-xs font-bold font-mono px-2.5 py-1 rounded border ${
              article.claim_status === 'confirmed'
                ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
            }`}>
              [{article.claim_status.toUpperCase()}]
            </span>
          )}

          {article.cyber_risk_score && (
            <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
              Risk Score: {article.cyber_risk_score}/100
            </span>
          )}

          <div className="ml-auto text-xs text-text-muted flex items-center gap-3">
            <span>{format(pubDate, 'dd MMMM yyyy, HH:mm')} UTC</span>
            <span>·</span>
            <span className="flex items-center gap-1"><Eye className="w-3.5 h-3.5" /> {article.view_count || 32} views</span>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-2xl sm:text-3xl font-bold text-text-primary font-display leading-tight tracking-tight">
          {article.title}
        </h1>

        {/* Threat Intelligence Metadata Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-lg bg-bg-elevated/40 border border-border">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-text-muted font-mono mb-1 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-rose-400" /> Attack Type
            </div>
            <div className="text-xs font-semibold text-text-primary">
              {article.attacks?.length > 0 ? article.attacks.join(', ') : article.attack_vector || 'Cyber Incident'}
            </div>
          </div>

          <div>
            <div className="text-[11px] uppercase tracking-wider text-text-muted font-mono mb-1 flex items-center gap-1">
              <Target className="w-3 h-3 text-blue-400" /> Target Sector
            </div>
            <div className="text-xs font-semibold text-text-primary">
              {article.targets?.length > 0 ? article.targets.join(', ') : article.sector || 'Enterprise'}
            </div>
          </div>

          <div>
            <div className="text-[11px] uppercase tracking-wider text-text-muted font-mono mb-1 flex items-center gap-1">
              <Globe className="w-3 h-3 text-emerald-400" /> Geography
            </div>
            <div className="text-xs font-semibold text-text-primary">
              {article.geography?.length > 0 ? article.geography.join(', ') : article.target_country || 'Global'}
            </div>
          </div>

          <div>
            <div className="text-[11px] uppercase tracking-wider text-text-muted font-mono mb-1 flex items-center gap-1">
              <Cpu className="w-3 h-3 text-purple-400" /> Threat Actor
            </div>
            <div className="text-xs font-semibold text-text-primary">
              {article.threat_actors?.length > 0 ? article.threat_actors.join(', ') : 'Unattributed'}
            </div>
          </div>
        </div>

        {/* Article Summary / Executive Brief */}
        {article.summary && (
          <div className="p-4 rounded-lg bg-primary/5 border border-primary/20 space-y-1.5">
            <div className="text-xs font-bold text-primary font-mono uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" /> Executive Intelligence Summary
            </div>
            <p className="text-xs sm:text-sm text-text-secondary leading-relaxed font-medium">
              {article.summary}
            </p>
          </div>
        )}

        {/* Detailed Report Content */}
        <div className="space-y-3 pt-2">
          <h3 className="text-xs font-bold font-mono uppercase text-text-muted tracking-wider">Detailed Analysis & Incident Narrative</h3>
          <div className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap space-y-4 font-sans bg-bg-surface/50 p-5 rounded-lg border border-border">
            {article.content_clean || article.content || 'Full incident briefing is being synchronized.'}
          </div>
        </div>

        {/* MITRE ATT&CK Techniques & Tags */}
        <div className="space-y-3 pt-2 border-t border-border">
          <h3 className="text-xs font-bold font-mono uppercase text-text-muted tracking-wider flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-accent-cyan" /> MITRE ATT&CK & Matched Keywords
          </h3>
          <div className="flex items-center gap-1.5 flex-wrap">
            {article.mitre_techniques?.map((tech: string) => (
              <span key={tech} className="text-xs font-mono px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                🛡️ {tech}
              </span>
            ))}
            {article.cves?.map((cve: string) => (
              <Link key={cve} href={`/kev/${cve}`}>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition-colors">
                  🔥 {cve}
                </span>
              </Link>
            ))}
            {article.all_matched_terms?.slice(0, 10).map((term: string) => (
              <span key={term} className="text-xs px-2 py-0.5 rounded bg-bg-elevated text-text-muted border border-border">
                #{term}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Extracted IOCs Section */}
      {hasIocs && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-text-primary text-sm flex items-center gap-2">
              <Database className="w-4 h-4 text-accent-cyan" /> Extracted Indicators of Compromise (IOCs)
            </h3>
            <span className="text-xs font-mono text-text-muted">{article.ioc_count || 0} indicators detected</span>
          </div>

          <div className="space-y-4">
            {Object.entries(iocs).map(([type, vals]: any) => (
              vals?.length > 0 && (
                <div key={type} className="space-y-1.5 p-3 rounded-lg bg-bg-elevated/30 border border-border">
                  <span className="text-xs font-mono text-accent-cyan uppercase font-bold">{type} ({vals.length})</span>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {vals.map((v: string, i: number) => (
                      <button
                        key={i}
                        onClick={() => handleCopy(v, type)}
                        className="text-xs font-mono bg-bg-elevated hover:bg-bg-elevated/80 px-2.5 py-1 rounded text-accent-cyan border border-border flex items-center gap-1.5 transition-colors group cursor-pointer"
                        title="Click to copy IOC"
                      >
                        <code>{v}</code>
                        {copiedText === v ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 opacity-40 group-hover:opacity-100 transition-opacity" />
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

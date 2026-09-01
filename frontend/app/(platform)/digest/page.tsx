'use client';

import { useQuery, useMutation } from '@tanstack/react-query';
import { digestApi } from '@/lib/api/client';
import { BookOpen, Sparkles, RefreshCw, Clock } from 'lucide-react';
import toast from 'react-hot-toast';

export default function DigestPage() {
  const { data: latest, isLoading, refetch } = useQuery({
    queryKey: ['digest', 'latest'],
    queryFn: () => digestApi.latest().then(r => r.data),
  });

  const generateMutation = useMutation({
    mutationFn: () => digestApi.generate(),
    onSuccess: () => {
      toast.success('Digest generation triggered!');
      setTimeout(refetch, 3000);
    },
    onError: () => toast.error('Failed to trigger digest'),
  });

  const digest = latest?.digest;

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-secondary/15 flex items-center justify-center text-secondary">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-text-primary font-display">AI Intelligence Digest</h2>
            <p className="text-xs text-text-muted">Automated 24-hour executive security briefing</p>
          </div>
        </div>
        <button
          onClick={() => generateMutation.mutate()}
          disabled={generateMutation.isPending}
          className="btn-primary flex items-center gap-2 text-xs"
        >
          <Sparkles className="w-3.5 h-3.5" />Generate Digest Now
        </button>
      </div>

      {isLoading ? (
        <div className="card p-8 skeleton h-64" />
      ) : !digest ? (
        <div className="card p-12 text-center">
          <BookOpen className="w-12 h-12 text-text-muted mx-auto mb-3" />
          <p className="text-text-secondary font-medium">No digest generated yet</p>
          <p className="text-xs text-text-muted mt-1">Click "Generate Digest Now" or wait for scheduled daily run.</p>
        </div>
      ) : (
        <div className="space-y-5">
          {/* Headline banner */}
          <div className="card p-6 bg-gradient-to-r from-bg-surface via-bg-elevated to-bg-surface border-secondary/30">
            <span className="text-[10px] font-bold uppercase tracking-widest text-secondary mb-2 block">Executive Headline</span>
            <h1 className="text-xl font-bold text-text-primary font-display leading-snug">{digest.headline}</h1>
            <p className="text-xs text-text-muted mt-3 leading-relaxed">{digest.todays_highlights}</p>
          </div>

          {/* Critical threats */}
          {digest.critical_threats?.length > 0 && (
            <div className="card p-5 space-y-3">
              <h3 className="font-semibold text-text-primary text-sm">Critical Threats Today</h3>
              <div className="space-y-2">
                {digest.critical_threats.map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-bg-elevated border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="w-1.5 h-1.5 bg-severity-critical rounded-full" />
                      <span className="font-semibold text-text-primary text-sm">{t.title}</span>
                      <span className="text-xs text-text-muted ml-auto">{t.source}</span>
                    </div>
                    <p className="text-xs text-text-muted leading-relaxed">{t.summary}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Trending lists */}
          <div className="grid grid-cols-3 gap-4">
            <div className="card p-4">
              <h4 className="text-xs font-semibold text-text-muted mb-2 uppercase tracking-wide">Threat Actors</h4>
              <ul className="space-y-1">
                {digest.trending_threat_actors?.map((a: string, i: number) => (
                  <li key={i} className="text-xs text-secondary font-medium">• {a}</li>
                ))}
              </ul>
            </div>
            <div className="card p-4">
              <h4 className="text-xs font-semibold text-text-muted mb-2 uppercase tracking-wide">Malware</h4>
              <ul className="space-y-1">
                {digest.trending_malware?.map((m: string, i: number) => (
                  <li key={i} className="text-xs text-accent-orange font-medium">• {m}</li>
                ))}
              </ul>
            </div>
            <div className="card p-4">
              <h4 className="text-xs font-semibold text-text-muted mb-2 uppercase tracking-wide">Targeted Vendors</h4>
              <ul className="space-y-1">
                {digest.trending_vendors?.map((v: string, i: number) => (
                  <li key={i} className="text-xs text-primary font-medium">• {v}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Analyst Note */}
          {digest.analyst_note && (
            <div className="card p-5 bg-primary/5 border-primary/20">
              <h4 className="text-xs font-semibold text-primary mb-1 uppercase tracking-wide">Analyst Recommendation</h4>
              <p className="text-xs text-text-secondary leading-relaxed">{digest.analyst_note}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

'use client';

import { useState, useRef, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clusterRulesApi } from '@/lib/api/client';
import {
  Layers, Building2, ShieldAlert, Bug, Globe,
  Filter, Plus, SquarePen, Trash2, Play, Eye, X, Check,
  Tag, MapPin, Briefcase, Zap, Clock, ArrowLeft, ArrowRight, ExternalLink, Search, RefreshCw, Power
} from 'lucide-react';
import Link from 'next/link';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';

const COUNTRY_OPTIONS = ['All', 'India', 'UAE', 'Saudi Arabia', 'Qatar', 'Kuwait', 'Bahrain', 'Oman', 'USA', 'UK', 'China', 'Russia', 'Germany', 'France', 'Australia', 'Japan', 'Brazil', 'Canada', 'Singapore'];
const SECTOR_OPTIONS = ['All', 'IT', 'Banking & Finance', 'Healthcare', 'Government', 'Education', 'Manufacturing', 'Retail', 'Energy & Utilities', 'Telecom', 'Defence', 'Insurance', 'Legal', 'Media & Entertainment'];
const INCIDENT_TYPES = ['All', 'Data breach', 'Ransomware', 'Data leak', 'Phishing', 'Supply chain attack', 'Zero-day exploit', 'DDoS', 'Malware', 'Insider threat', 'Vulnerability', 'Cyber Advisory'];
const EMPTY_FORM = { name: '', description: '', keywords: [] as string[], country: 'All', sectors: ['All'] as string[], incident_type: 'All', enabled: true };

function KeywordInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [inputVal, setInputVal] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const addKeyword = () => {
    const kw = inputVal.trim().toUpperCase();
    if (kw && !value.includes(kw)) onChange([...value, kw]);
    setInputVal('');
  };
  const removeKeyword = (kw: string) => onChange(value.filter((k) => k !== kw));
  return (
    <div className="min-h-[42px] flex flex-wrap gap-1.5 p-2 rounded-xl border border-border bg-bg-elevated focus-within:border-primary/50 transition-colors cursor-text" onClick={() => inputRef.current?.focus()}>
      {value.map((kw) => (
        <span key={kw} className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-primary/15 text-primary border border-primary/25 text-[11px] font-bold font-mono">
          {kw}
          <button type="button" onClick={(e) => { e.stopPropagation(); removeKeyword(kw); }} className="hover:text-red-400 transition-colors"><X className="w-2.5 h-2.5" /></button>
        </span>
      ))}
      <input ref={inputRef} value={inputVal} onChange={(e) => setInputVal(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addKeyword(); }
          if (e.key === 'Backspace' && !inputVal && value.length > 0) removeKeyword(value[value.length - 1]);
        }}
        placeholder={value.length === 0 ? 'Type keyword + Enter to add...' : ''}
        className="flex-1 min-w-[140px] bg-transparent text-xs text-text-primary outline-none placeholder:text-text-muted" />
      {inputVal && <button type="button" onClick={addKeyword} className="text-[11px] text-primary font-bold px-1.5 py-0.5 rounded bg-primary/10 hover:bg-primary/20 transition">+ Add</button>}
    </div>
  );
}

function SectorMultiSelect({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const toggle = (s: string) => {
    if (s === 'All') { onChange(['All']); return; }
    const next = value.filter((x) => x !== 'All').includes(s) ? value.filter((x) => x !== s) : [...value.filter((x) => x !== 'All'), s];
    onChange(next.length === 0 ? ['All'] : next);
  };
  return (
    <div className="flex flex-wrap gap-1.5">
      {SECTOR_OPTIONS.map((s) => (
        <button key={s} type="button" onClick={() => toggle(s)}
          className={clsx('px-2.5 py-1 rounded-lg text-[11px] font-medium border transition-all',
            value.includes(s) ? 'bg-primary/20 text-primary border-primary/40 font-semibold' : 'bg-bg-surface text-text-secondary border-border hover:border-primary/30')}>
          {s}
        </button>
      ))}
    </div>
  );
}

function RuleModal({ rule, onClose, onSave, isSaving }: { rule: any | null; onClose: () => void; onSave: (data: any) => void; isSaving: boolean }) {
  const [form, setForm] = useState(rule ? {
    name: rule.name, description: rule.description, keywords: rule.keywords ?? [],
    country: rule.country ?? 'All', sectors: rule.sectors ?? ['All'],
    incident_type: rule.incident_type ?? 'All', enabled: rule.enabled ?? true,
  } : { ...EMPTY_FORM });
  const set = (key: string, val: any) => setForm((f) => ({ ...f, [key]: val }));
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-xl bg-bg-surface rounded-2xl border border-border shadow-2xl flex flex-col max-h-[90vh] overflow-hidden animate-in fade-in zoom-in-95">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-bg-surface/80">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-primary/15 text-primary flex items-center justify-center border border-primary/20"><Filter className="w-4 h-4" /></div>
            <div>
              <h2 className="font-bold text-text-primary text-sm">{rule ? 'Edit Cluster Rule' : 'Create Intelligence Cluster'}</h2>
              <p className="text-[11px] text-text-muted">Define filters to auto-group matching cyber threat news</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-bg-input text-text-muted hover:text-text-primary transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Cluster Name <span className="text-red-400">*</span></label>
            <input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. GCC & Middle East Banking Threats"
              className="w-full px-3 py-2 rounded-xl border border-border bg-bg-elevated text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-primary/50 transition-colors" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Description</label>
            <textarea value={form.description} onChange={(e) => set('description', e.target.value)} placeholder="What threat intelligence does this cluster track?" rows={2}
              className="w-full px-3 py-2 rounded-xl border border-border bg-bg-elevated text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-primary/50 transition-colors resize-none" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Target Country</label>
            <select value={form.country} onChange={(e) => set('country', e.target.value)}
              className="w-full px-3 py-2 rounded-xl border border-border bg-bg-elevated text-xs text-text-primary outline-none focus:border-primary/50">
              {COUNTRY_OPTIONS.map((c) => (<option key={c} value={c}>{c === 'All' ? '🌍 All Countries' : `📍 ${c}`}</option>))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Incident Type</label>
            <select value={form.incident_type} onChange={(e) => set('incident_type', e.target.value)}
              className="w-full px-3 py-2 rounded-xl border border-border bg-bg-elevated text-xs text-text-primary outline-none focus:border-primary/50">
              {INCIDENT_TYPES.map((t) => (<option key={t} value={t}>{t === 'All' ? '⚡ All Incident Types' : `🛡️ ${t}`}</option>))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Target Sectors</label>
            <SectorMultiSelect value={form.sectors} onChange={(s) => set('sectors', s)} />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary mb-1.5">Required Keywords <span className="text-[10px] text-text-muted">(Enter keywords to match in title or summary)</span></label>
            <KeywordInput value={form.keywords} onChange={(k) => set('keywords', k)} />
          </div>
        </div>
        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-bg-surface/80">
          <label className="flex items-center gap-2 cursor-pointer text-xs font-medium text-text-secondary">
            <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} className="rounded text-primary focus:ring-0" />
            Rule Enabled
          </label>
          <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-xl border border-border text-xs text-text-secondary hover:text-text-primary hover:bg-bg-input transition-colors">Cancel</button>
            <button type="button" disabled={!form.name.trim() || isSaving} onClick={() => onSave(form)}
              className="px-5 py-2 rounded-xl bg-primary text-white text-xs font-bold hover:bg-primary/90 disabled:opacity-50 transition-colors shadow-glow-primary flex items-center gap-1.5">
              <Check className="w-3.5 h-3.5" />
              {isSaving ? 'Saving...' : rule ? 'Update Cluster' : 'Save Cluster'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ClustersPage() {
  const queryClient = useQueryClient();
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedRuleName, setSelectedRuleName] = useState<string | null>(null);
  const [filterSearch, setFilterSearch] = useState('');
  const [editingRule, setEditingRule] = useState<any | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const { data: rulesRes, isLoading: loadingRules, refetch: refetchRules } = useQuery({
    queryKey: ['clusterRules'],
    queryFn: () => clusterRulesApi.list().then((r) => r.data),
  });

  const { data: runRes, isLoading: loadingRun } = useQuery({
    queryKey: ['runRule', selectedRuleId],
    queryFn: () => clusterRulesApi.run(selectedRuleId!).then((r) => r.data),
    enabled: !!selectedRuleId,
  });

  const createRuleMut = useMutation({
    mutationFn: (data: any) => clusterRulesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusterRules'] });
      setIsModalOpen(false);
    },
  });

  const updateRuleMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => clusterRulesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusterRules'] });
      setIsModalOpen(false);
      setEditingRule(null);
    },
  });

  const deleteRuleMut = useMutation({
    mutationFn: (id: string) => clusterRulesApi.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['clusterRules'] });
      if (selectedRuleId) setSelectedRuleId(null);
    },
  });

  const rules: any[] = rulesRes?.data ?? [];
  const rawArticles: any[] = runRes?.data?.articles ?? [];

  const activeRuleArticles = useMemo(() => {
    if (!filterSearch.trim()) return rawArticles;
    const term = filterSearch.toLowerCase();
    return rawArticles.filter((art: any) =>
      (art.title || '').toLowerCase().includes(term) ||
      (art.summary || '').toLowerCase().includes(term) ||
      (art.source_name || '').toLowerCase().includes(term)
    );
  }, [rawArticles, filterSearch]);

  return (
    <div className="min-h-screen bg-bg-base p-6 space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-[11px] font-bold tracking-wide uppercase flex items-center gap-1">
              <Layers className="w-3 h-3" /> Manage Threat Clusters
            </span>
          </div>
          <h1 className="text-xl font-bold text-text-primary font-display">Manage Intelligence Clusters</h1>
          <p className="text-xs text-text-muted">Configure custom cyber threat discovery rules and view matching incident news feeds.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetchRules()} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-border bg-bg-surface text-xs text-text-secondary hover:text-text-primary hover:bg-bg-input transition-colors">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          <button onClick={() => { setEditingRule(null); setIsModalOpen(true); }} className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-primary text-white text-xs font-bold hover:bg-primary/90 transition-colors shadow-glow-primary">
            <Plus className="w-4 h-4" /> Create Cluster Rule
          </button>
        </div>
      </div>

      {/* Main Content */}
      {selectedRuleId ? (
        /* Matched Articles View for Selected Rule */
        <div className="space-y-5">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-bg-surface p-4 rounded-2xl border border-border">
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  setSelectedRuleId(null);
                  setFilterSearch('');
                }}
                className="p-2 rounded-xl border border-border hover:bg-bg-input text-text-secondary hover:text-text-primary transition-colors"
                title="Back to All Clusters"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-primary">Matched News Cluster</span>
                <h2 className="text-base font-bold text-text-primary">{selectedRuleName}</h2>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="relative w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  value={filterSearch}
                  onChange={(e) => setFilterSearch(e.target.value)}
                  placeholder="Filter in matched news..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-xl border border-border bg-bg-elevated text-xs text-text-primary outline-none focus:border-primary/50"
                />
              </div>
              <span className="text-xs font-mono text-text-muted bg-bg-elevated px-2.5 py-1.5 rounded-xl border border-border whitespace-nowrap">
                {activeRuleArticles.length} Articles
              </span>
            </div>
          </div>

          {loadingRun ? (
            <div className="py-16 text-center text-xs text-text-muted animate-pulse">Running cluster discovery query and retrieving matched articles...</div>
          ) : activeRuleArticles.length === 0 ? (
            <div className="py-16 text-center bg-bg-surface rounded-2xl border border-border p-8 space-y-2">
              <ShieldAlert className="w-8 h-8 text-text-muted mx-auto" />
              <p className="text-sm font-semibold text-text-primary">No articles currently match this cluster rule</p>
              <p className="text-xs text-text-muted">Try adjusting the keywords, sectors, or country filters in the rule editor.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {activeRuleArticles.map((art: any) => (
                <div key={art.id || art._id} className="p-4 rounded-2xl border border-border bg-bg-surface hover:border-primary/40 transition-all flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between text-[11px] text-text-muted mb-1.5">
                      <span className="font-semibold text-primary">{art.source_name}</span>
                      <span>{art.published_at ? formatDistanceToNow(new Date(art.published_at), { addSuffix: true }) : ''}</span>
                    </div>
                    <Link href={`/feed/${art.id || art._id}`}>
                      <h3 className="font-bold text-sm text-text-primary hover:text-primary transition-colors line-clamp-2 cursor-pointer">{art.title}</h3>
                    </Link>
                    <p className="text-xs text-text-secondary mt-1.5 line-clamp-3">{art.summary || art.content_clean}</p>
                  </div>
                  <div className="flex items-center justify-between pt-2 border-t border-border/50 text-[11px]">
                    <span className={clsx('px-2 py-0.5 rounded text-[10px] font-bold uppercase', String(art.severity).toLowerCase() === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400')}>
                      {art.severity || 'HIGH'}
                    </span>
                    <div className="flex items-center gap-2">
                      <Link href={`/feed/${art.id || art._id}`} className="flex items-center gap-1 text-primary hover:underline font-semibold">
                        Read Article <ArrowRight className="w-3 h-3" />
                      </Link>
                      {art.url && !art.url.startsWith('/') && !art.url.includes('localhost') && (
                        <a href={art.url} target="_blank" rel="noreferrer" className="text-text-muted hover:text-primary transition-colors p-0.5" title="Original Website">
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        /* Manage Cluster Rules Grid */
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-text-muted uppercase tracking-wider">Configured Cluster Rules ({rules.length})</span>
          </div>

          {loadingRules ? (
            <div className="py-12 text-center text-xs text-text-muted animate-pulse">Loading cluster rules...</div>
          ) : rules.length === 0 ? (
            <div className="text-center bg-bg-surface rounded-2xl border border-border p-12 space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-primary/10 text-primary flex items-center justify-center mx-auto border border-primary/20">
                <Layers className="w-6 h-6" />
              </div>
              <h3 className="font-bold text-base text-text-primary">No Cluster Rules Created Yet</h3>
              <p className="text-xs text-text-muted max-w-md mx-auto">Create custom discovery rules to cluster threat intelligence reports by country, sector, incident type, or custom keywords.</p>
              <button onClick={() => { setEditingRule(null); setIsModalOpen(true); }} className="mt-2 inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-primary text-white text-xs font-bold hover:bg-primary/90 transition-colors shadow-glow-primary">
                <Plus className="w-4 h-4" /> Create Your First Cluster Rule
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {rules.map((r: any) => (
                <div key={r.id || r._id} className="p-5 rounded-2xl border border-border bg-bg-surface hover:border-primary/50 transition-all flex flex-col justify-between space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className={clsx('px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider', r.enabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-bg-input text-text-muted border border-border')}>
                        {r.enabled ? 'ACTIVE' : 'PAUSED'}
                      </span>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => updateRuleMut.mutate({ id: r.id || r._id, data: { ...r, enabled: !r.enabled } })}
                          className="p-1.5 rounded-lg border border-border hover:bg-bg-input text-text-muted hover:text-text-primary transition-colors"
                          title={r.enabled ? 'Pause Rule' : 'Activate Rule'}
                        >
                          <Power className={clsx('w-3.5 h-3.5', r.enabled ? 'text-emerald-400' : 'text-text-muted')} />
                        </button>
                        <button onClick={() => { setEditingRule(r); setIsModalOpen(true); }} className="p-1.5 rounded-lg border border-border hover:bg-bg-input text-text-muted hover:text-text-primary transition-colors" title="Edit Rule">
                          <SquarePen className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => deleteRuleMut.mutate(r.id || r._id)} className="p-1.5 rounded-lg border border-border hover:bg-red-500/10 text-text-muted hover:text-red-400 transition-colors" title="Delete Rule">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <h3 className="font-bold text-base text-text-primary">{r.name}</h3>
                    <p className="text-xs text-text-muted mt-1 line-clamp-2">{r.description || 'No description provided.'}</p>

                    <div className="flex flex-wrap gap-1.5 pt-3">
                      {r.country && r.country !== 'All' && (
                        <span className="px-2 py-0.5 rounded-md bg-bg-elevated border border-border text-[10px] text-text-secondary font-medium">📍 {r.country}</span>
                      )}
                      {r.incident_type && r.incident_type !== 'All' && (
                        <span className="px-2 py-0.5 rounded-md bg-accent-orange/10 border border-accent-orange/20 text-[10px] text-accent-orange font-medium">🛡️ {r.incident_type}</span>
                      )}
                      {r.keywords?.map((kw: string) => (
                        <span key={kw} className="px-2 py-0.5 rounded-md bg-primary/10 border border-primary/20 text-[10px] font-mono text-primary font-bold">{kw}</span>
                      ))}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-border flex items-center justify-between">
                    <button
                      onClick={() => {
                        setSelectedRuleId(r.id || r._id);
                        setSelectedRuleName(r.name);
                        setFilterSearch('');
                      }}
                      className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-xl bg-primary/10 border border-primary/20 text-xs font-bold text-primary hover:bg-primary hover:text-white transition-all shadow-sm"
                    >
                      <Eye className="w-3.5 h-3.5" /> View Matched News
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal */}
      {isModalOpen && (
        <RuleModal
          rule={editingRule}
          onClose={() => setIsModalOpen(false)}
          onSave={(data) => {
            if (editingRule) {
              updateRuleMut.mutate({ id: editingRule.id || editingRule._id, data });
            } else {
              createRuleMut.mutate(data);
            }
          }}
          isSaving={createRuleMut.isPending || updateRuleMut.isPending}
        />
      )}
    </div>
  );
}

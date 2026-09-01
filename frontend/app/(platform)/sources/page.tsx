'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { sourcesApi } from '@/lib/api/client';
import { Globe, CheckCircle, Plus, Sparkles, X, RefreshCw, ShieldAlert, Cpu, FileText, Check } from 'lucide-react';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { toast } from 'react-hot-toast';

export default function SourcesPage() {
  const [showAddModal, setShowAddModal] = useState(false);
  const [inputUrl, setInputUrl] = useState('');
  const [inputName, setInputName] = useState('');
  const [inputCategory, setInputCategory] = useState('news');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [aiSummaryResult, setAiSummaryResult] = useState<any>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['sources'],
    queryFn: () => sourcesApi.list({}).then(r => r.data),
  });

  const sources = data?.data ?? [];

  const handleAddUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim() || !inputUrl.startsWith('http')) {
      return toast.error('Please enter a valid URL starting with http:// or https://');
    }

    setIsSubmitting(true);
    setAiSummaryResult(null);

    try {
      const res = await sourcesApi.addUrl({
        url: inputUrl.trim(),
        name: inputName.trim() || undefined,
        category: inputCategory,
      });

      toast.success('Website URL added & 2-Part AI Summary generated!');
      setAiSummaryResult(res.data.summary);
      refetch();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add source URL');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-lg font-bold text-text-primary font-display">Intelligence Sources</h2>
          <p className="text-xs text-text-muted">{sources.length} active feeds, web pages, and CERT advisories monitored continuously</p>
        </div>

        <button
          onClick={() => {
            setShowAddModal(true);
            setAiSummaryResult(null);
          }}
          className="px-4 py-2.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-xl flex items-center gap-2 transition-all shadow-glow-primary"
        >
          <Plus className="w-4 h-4" />
          Add Website URL / Source
        </button>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          Array.from({ length: 9 }).map((_, i) => (
            <div key={i} className="card p-5 h-32 skeleton" />
          ))
        ) : (
          sources.map((src: any) => (
            <div key={src.id} className="card p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className={clsx('text-[10px] font-bold px-2 py-0.5 rounded border uppercase',
                    src.category === 'vendor' ? 'bg-primary/10 text-primary border-primary/20' :
                    src.category === 'news'   ? 'bg-secondary/10 text-secondary border-secondary/20' :
                                               'bg-accent-green/10 text-accent-green border-accent-green/20'
                  )}>
                    {src.category}
                  </span>
                  <span className={clsx('flex items-center gap-1 text-[10px]',
                    src.health_status === 'healthy' ? 'text-accent-green' : 'text-severity-high'
                  )}>
                    <CheckCircle className="w-3 h-3" />
                    {src.health_status || 'healthy'}
                  </span>
                </div>

                <h3 className="font-bold text-text-primary text-sm mb-1">{src.name}</h3>

                <div className="flex items-center gap-1 text-[11px] text-text-muted flex-wrap">
                  {src.tags?.map((t: string) => (
                    <span key={t} className="tag">{t}</span>
                  ))}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-[11px] text-text-muted">
                <span>{src.article_count || 0} articles</span>
                <span>
                  {src.last_crawled_at ? formatDistanceToNow(new Date(src.last_crawled_at), { addSuffix: true }) : 'Never crawled'}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add Website URL & 2-Part AI Summary Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-bg-surface border border-border rounded-2xl p-6 max-w-2xl w-full space-y-5 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-border pb-4">
              <div className="flex items-center gap-2">
                <div className="p-2 bg-secondary/10 text-secondary rounded-xl border border-secondary/20">
                  <Sparkles className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-text-primary font-display">Add Website URL / Source</h3>
                  <p className="text-xs text-text-muted">Extracts content & generates a 2-Part AI Summary</p>
                </div>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-text-muted hover:text-text-primary p-1 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddUrl} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Website / Article URL *
                </label>
                <input
                  type="url"
                  required
                  placeholder="https://example-security-blog.com/post/123"
                  value={inputUrl}
                  onChange={e => setInputUrl(e.target.value)}
                  className="w-full bg-bg-base border border-border rounded-xl text-xs text-text-primary placeholder-text-muted px-3.5 py-2.5 focus:outline-none focus:border-primary transition-colors font-mono"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                    Source Display Name (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. CyberSec Advisory Post"
                    value={inputName}
                    onChange={e => setInputName(e.target.value)}
                    className="w-full bg-bg-base border border-border rounded-xl text-xs text-text-primary placeholder-text-muted px-3.5 py-2.5 focus:outline-none focus:border-primary transition-colors"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                    Category
                  </label>
                  <select
                    value={inputCategory}
                    onChange={e => setInputCategory(e.target.value)}
                    className="w-full bg-bg-base border border-border rounded-xl text-xs text-text-primary px-3.5 py-2.5 focus:outline-none focus:border-primary transition-colors"
                  >
                    <option value="news">News & Media</option>
                    <option value="vendor">Vendor Research</option>
                    <option value="cert">CERT Advisory</option>
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting || !inputUrl.trim()}
                className="w-full py-2.5 bg-primary hover:bg-primary-hover disabled:opacity-50 text-white font-semibold text-xs rounded-xl transition-all flex items-center justify-center gap-2 shadow-glow-primary"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Analyzing Website URL & Generating 2-Part AI Summary...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    Analyze & Generate 2-Part AI Summary
                  </>
                )}
              </button>
            </form>

            {/* Generated 2-Part AI Summary Result View */}
            {aiSummaryResult && (
              <div className="mt-6 pt-5 border-t border-border space-y-4 animate-fade-in">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-secondary" />
                  <h4 className="text-xs font-bold text-text-primary uppercase tracking-wider">
                    Generated 2-Part AI Summary Output
                  </h4>
                </div>

                {/* Part 1: Key Intelligence Summary */}
                <div className="bg-gradient-to-br from-bg-base to-secondary/5 border border-secondary/20 p-4 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-secondary font-mono flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" /> Part 1: Key Intelligence Summary
                    </span>
                    <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-secondary/20 text-secondary border border-secondary/30">
                      {aiSummaryResult.part_1_key_intelligence?.severity || 'HIGH'}
                    </span>
                  </div>

                  <p className="text-xs text-text-secondary leading-relaxed">
                    {aiSummaryResult.part_1_key_intelligence?.overview}
                  </p>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-2 border-t border-secondary/10 text-[11px]">
                    <div>
                      <span className="text-text-muted block text-[10px]">Company:</span>
                      <span className="font-semibold text-text-primary">{aiSummaryResult.part_1_key_intelligence?.target_company}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block text-[10px]">Country:</span>
                      <span className="font-semibold text-text-primary">{aiSummaryResult.part_1_key_intelligence?.target_country}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block text-[10px]">Incident Type:</span>
                      <span className="font-semibold text-text-primary">{aiSummaryResult.part_1_key_intelligence?.incident_type}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block text-[10px]">Sector:</span>
                      <span className="font-semibold text-text-primary">{aiSummaryResult.part_1_key_intelligence?.sector}</span>
                    </div>
                  </div>
                </div>

                {/* Part 2: Technical & IOC Analysis */}
                <div className="bg-gradient-to-br from-bg-base to-primary/5 border border-primary/20 p-4 rounded-xl space-y-3">
                  <span className="text-xs font-bold text-primary font-mono flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" /> Part 2: Technical & IOC Analysis
                  </span>

                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-text-muted block text-[10px] mb-1">Extracted CVEs:</span>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {aiSummaryResult.part_2_technical_ioc_analysis?.extracted_cves?.length > 0 ? (
                          aiSummaryResult.part_2_technical_ioc_analysis.extracted_cves.map((cve: string) => (
                            <span key={cve} className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                              {cve}
                            </span>
                          ))
                        ) : (
                          <span className="text-text-muted text-[11px] italic">No direct CVEs identified in text</span>
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="text-text-muted block text-[10px] mb-1">Recommended Mitigation Steps:</span>
                      <ul className="space-y-1">
                        {aiSummaryResult.part_2_technical_ioc_analysis?.mitigation_steps?.map((step: string, i: number) => (
                          <li key={i} className="flex items-start gap-1.5 text-text-secondary text-[11px]">
                            <Check className="w-3.5 h-3.5 text-accent-green flex-shrink-0 mt-0.5" />
                            <span>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

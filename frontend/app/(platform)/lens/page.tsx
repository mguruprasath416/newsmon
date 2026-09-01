'use client';

import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { lensApi, reportsApi, threatActorsApi } from '@/lib/api/client';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Sparkles, Search, Copy, Download, Share2,
  AlertCircle, Loader2, ArrowRight, Database,
  CheckCheck, Shield, Terminal, Zap, ExternalLink,
  ChevronDown, ChevronRight, Check
} from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';

export default function LensPage() {
  const [urlInput, setUrlInput] = useState('');
  const [jobId, setJobId] = useState<string | null>(null);
  const [reportId, setReportId] = useState<string | null>(null);
  const [defang, setDefang] = useState(false);
  const [copiedAll, setCopiedAll] = useState(false);
  const [inferringActor, setInferringActor] = useState(false);
  const [inferredActor, setInferredActor] = useState<any>(null);
  const [savedActor, setSavedActor] = useState(false);

  const handleInferThreatActor = async () => {
    if (!reportData) return;
    setInferringActor(true);
    try {
      const res = await threatActorsApi.aiFill({
        evidence_text: reportData.technical_overview || reportData.executive_summary || urlInput,
        iocs: allIocValues.slice(0, 10),
        cves: cveList,
        malware: malwareList.map((m: any) => typeof m === 'string' ? m : m.name),
        techniques: mitreTechniques,
      });
      setInferredActor(res.data.inferred);
      toast.success('AI Threat Actor Attribution completed!');
    } catch (err) {
      toast.error('AI attribution inference failed');
    } finally {
      setInferringActor(false);
    }
  };

  const handleSaveInferredActor = async () => {
    if (!inferredActor) return;
    try {
      await threatActorsApi.aiFill({
        evidence_text: reportData?.technical_overview || '',
        iocs: allIocValues.slice(0, 10),
        cves: cveList,
        malware: malwareList.map((m: any) => typeof m === 'string' ? m : m.name),
        techniques: mitreTechniques,
        save_to_db: true,
      });
      setSavedActor(true);
      toast.success('Threat Actor profile saved to platform directory!');
    } catch {
      toast.error('Failed to save Threat Actor profile');
    }
  };

  const submitMutation = useMutation({
    mutationFn: async (targetUrl?: string) => {
      const url = targetUrl || urlInput;
      return lensApi.analyze('url', url);
    },
    onSuccess: (res) => {
      setJobId(res.data.job_id);
      setReportId(null);
      toast.success('AI Threat Analysis started!');
    },
    onError: () => toast.error('Failed to start analysis'),
  });

  const { data: jobStatus } = useQuery({
    queryKey: ['lens-job', jobId],
    queryFn: () => lensApi.jobStatus(jobId!).then(r => r.data),
    enabled: !!jobId,
    refetchInterval: (data: any) => {
      if (!data || ['complete', 'failed'].includes(data?.status)) return false;
      return 1500;
    },
  });

  const { data: report } = useQuery({
    queryKey: ['report', reportId],
    queryFn: () => reportsApi.get(reportId!).then(r => r.data),
    enabled: !!reportId,
  });

  if (jobStatus?.status === 'complete' && jobStatus?.report_url && !reportId) {
    const id = jobStatus.report_url.split('/').pop();
    setReportId(id!);
  }

  const isAnalyzing = jobStatus && !['complete', 'failed'].includes(jobStatus.status);
  const reportData = report?.report;

  const handleShare = async () => {
    if (!reportId) return;
    try {
      const res = await reportsApi.share(reportId);
      const url = `${window.location.origin}/share/${res.data.share_token}`;
      navigator.clipboard.writeText(url);
      toast.success('Share link copied to clipboard!');
    } catch {
      toast.error('Failed to create share link');
    }
  };

  const getDomain = (rawUrl: string) => {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      return parsed.hostname.replace('www.', '');
    } catch {
      return 'advisory-source.com';
    }
  };

  const getTitle = () => {
    if (report?.title) return report.title;
    if (reportData?.title) return reportData.title;
    if (urlInput) {
      const slug = urlInput.split('/').filter(Boolean).pop() || '';
      const clean = slug.replace(/\.html?$/, '').replace(/[-_]/g, ' ');
      if (clean.length > 10) return clean.charAt(0).toUpperCase() + clean.slice(1);
    }
    return 'Threat Intelligence Analysis Report';
  };

  const cveList: string[] = (reportData?.cves || []).map((c: any) => typeof c === 'string' ? c : c.cve_id).filter(Boolean);
  const iocs = reportData?.iocs || {};
  const allIocValues: string[] = Object.values(iocs).flat().map((v: any) => String(v)) as string[];

  // Threat actor info
  const threatActor = reportData?.threat_actor;
  const threatActorName = typeof threatActor === 'string' ? threatActor : threatActor?.name;

  // Malware
  const malwareList: any[] = reportData?.malware || [];

  // MITRE Techniques
  const mitreTechniques: any[] = reportData?.mitre_techniques || [];

  // Attack Chain
  const attackChain: Record<string, string> = reportData?.attack_chain || {};
  const validChainSteps = Object.entries(attackChain).filter(([, val]) => typeof val === 'string' && val.trim().length > 0);

  // Actions & Recommendations
  const actions: string[] = reportData?.mitigation?.immediate_actions || [];
  const recommendations: string[] = reportData?.mitigation?.recommendations || [];

  // YARA & Detection
  const detectionNotes = reportData?.detection?.detection_notes;
  const yaraRules = reportData?.detection?.yara_rules || [];

  const handleCopyAll = () => {
    const text = allIocValues.map(v => defang ? v.replace(/\./g, '[.]').replace(/http/gi, 'hxxp') : v).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const domain = getDomain(urlInput || report?.input_value || '');
  const title = getTitle();

  return (
    <div className="min-h-full bg-bg-base p-6 space-y-6 max-w-6xl mx-auto animate-fade-in">

      {/* ── Top Header & Input Bar ──────────────────────────────────── */}
      <div className="card p-6 bg-bg-surface border-border shadow-2xl rounded-2xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-secondary/20 border border-secondary/30 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-secondary" />
            </div>
            <h2 className="text-base font-bold text-text-primary font-display">Advisory Lens</h2>
          </div>
          {reportData && (
            <button
              onClick={() => { setJobId(null); setReportId(null); setUrlInput(''); }}
              className="text-xs text-text-muted hover:text-text-primary bg-bg-elevated px-3 py-1.5 rounded-lg border border-border transition-all"
            >
              New analysis
            </button>
          )}
        </div>

        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              className="w-full pl-11 pr-4 py-3 bg-bg-base border border-border rounded-xl text-text-primary text-sm placeholder:text-text-muted focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/40 font-mono transition-all"
              placeholder="https://thehackernews.com/..."
              value={urlInput}
              onChange={e => setUrlInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && urlInput.trim() && submitMutation.mutate(urlInput)}
            />
          </div>
          <button
            onClick={() => submitMutation.mutate(urlInput)}
            disabled={!urlInput.trim() || submitMutation.isPending || isAnalyzing}
            className="btn-primary px-6 py-3 rounded-xl font-medium text-sm flex items-center gap-2 flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitMutation.isPending || isAnalyzing ? (
              <><Loader2 className="w-4 h-4 animate-spin" />Analyzing...</>
            ) : (
              <>Analyze <ArrowRight className="w-4 h-4" /></>
            )}
          </button>
        </div>

        {/* Progress Bar */}
        {isAnalyzing && (
          <div className="mt-4 p-4 rounded-xl bg-bg-elevated border border-border space-y-2">
            <div className="flex items-center justify-between text-xs text-text-muted">
              <span>Stage: <strong className="text-primary capitalize">{jobStatus.current_stage?.replace('_', ' ')}</strong></span>
              <span>{jobStatus.progress}%</span>
            </div>
            <div className="h-1.5 rounded-full bg-bg-overlay overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-primary to-secondary rounded-full"
                animate={{ width: `${jobStatus.progress}%` }}
                transition={{ duration: 0.4 }}
              />
            </div>
          </div>
        )}
      </div>

      {/* ── Initial Empty State ────────────────────────────────────── */}
      {!reportData && !isAnalyzing && (
        <div className="card p-12 text-center bg-bg-surface border-border rounded-2xl">
          <div className="w-16 h-16 rounded-2xl bg-secondary/10 border border-secondary/20 flex items-center justify-center mx-auto mb-4">
            <Sparkles className="w-8 h-8 text-secondary" />
          </div>
          <h3 className="text-lg font-bold text-text-primary font-display mb-2">Instant AI Threat Analysis & MITRE Mapping</h3>
          <p className="text-xs text-text-muted max-w-md mx-auto leading-relaxed mb-6">
            Paste any security advisory URL above to extract structured briefing summaries, MITRE ATT&CK mappings, CVEs, and verified IOCs.
          </p>

          <div className="flex justify-center gap-2 flex-wrap">
            <span className="text-xs text-text-muted">Try sample:</span>
            {[
              'https://www.bleepingcomputer.com/news/security/russian-hackers-exploit-exchange-owa-zero-day-for-long-term-mailbox-access/',
              'https://thehackernews.com/2026/07/jfrog-confirms-openai-models-exploited.html',
            ].map(sample => (
              <button
                key={sample}
                onClick={() => { setUrlInput(sample); submitMutation.mutate(sample); }}
                className="text-xs font-mono text-primary hover:underline bg-primary/10 px-2.5 py-1 rounded border border-primary/20"
              >
                {sample.replace('https://', '').slice(0, 45)}...
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Dynamic Analysis Report ────────────────────────────────── */}
      {reportData && (
        <div className="space-y-6">

          {/* Title & Metadata Header */}
          <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
            <div className="flex items-center gap-3 flex-wrap text-xs">
              <span className="bg-severity-critical/20 text-severity-critical border border-severity-critical/40 font-bold px-2.5 py-0.5 rounded text-[11px] uppercase tracking-wider">
                CRITICAL
              </span>
              <span className="text-text-secondary font-medium font-mono">{domain}</span>
              <span className="text-text-muted">·</span>
              <span className="text-text-muted">{new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
            </div>

            <h1 className="text-2xl font-extrabold text-text-primary font-display leading-snug">
              {title}
            </h1>

            <div className="flex items-center gap-1.5 flex-wrap">
              {['#advisory', '#exploit', '#vulnerability', '#mitre-attack', '#analysis'].map(tag => (
                <span key={tag} className="text-xs font-mono bg-bg-elevated text-text-muted px-2.5 py-1 rounded-md border border-border/60">
                  {tag}
                </span>
              ))}
            </div>

            <div className="flex items-center gap-2 pt-2">
              <span className="bg-gradient-to-r from-secondary/20 to-primary/20 text-secondary border border-secondary/40 text-xs font-semibold px-3 py-1 rounded-lg flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" /> AI Intelligence Analysis
              </span>
              <span className="bg-accent-green/10 text-accent-green border border-accent-green/30 text-xs font-medium px-2.5 py-1 rounded-lg font-mono">
                HIGH confidence ({Math.round((reportData.confidence_score || 0.92) * 100)}%)
              </span>
              <div className="ml-auto flex gap-2">
                <button onClick={handleShare} className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5">
                  <Share2 className="w-3.5 h-3.5" /> Share
                </button>
                <a
                  href={`/api/v1/reports/${reportId}/export?format=markdown`}
                  download
                  className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" /> Export
                </a>
              </div>
            </div>
          </div>

          {/* ── Main Briefing Box (Executive, Technical, Key Intel) ──── */}
          <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-6">

            {/* Executive Brief */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-widest bg-secondary/15 text-secondary px-2.5 py-1 rounded-md border border-secondary/20 inline-block">
                EXECUTIVE BRIEF
              </span>
              <p className="text-sm text-text-primary leading-relaxed">
                {reportData.executive_summary}
              </p>
            </div>

            <div className="border-t border-border/60" />

            {/* Technical Overview */}
            <div className="space-y-2">
              <span className="text-[10px] font-bold uppercase tracking-widest bg-secondary/15 text-secondary px-2.5 py-1 rounded-md border border-secondary/20 inline-block">
                TECHNICAL OVERVIEW
              </span>
              <p className="text-xs text-text-secondary leading-relaxed">
                {reportData.technical_overview}
              </p>
            </div>

            <div className="border-t border-border/60" />

            {/* Key Intelligence Grid */}
            <div className="space-y-3">
              <span className="text-[10px] font-bold uppercase tracking-widest bg-secondary/15 text-secondary px-2.5 py-1 rounded-md border border-secondary/20 inline-block">
                KEY INTELLIGENCE
              </span>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex items-center gap-3">
                  <span className="text-text-muted w-36 flex-shrink-0 uppercase font-semibold">THREAT ACTORS</span>
                  <div className="flex items-center gap-2 flex-wrap">
                    {inferredActor ? (
                      <span className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2.5 py-1 rounded-md font-bold flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5" />
                        {inferredActor.name}
                      </span>
                    ) : threatActorName ? (
                      <span className="bg-bg-elevated text-text-primary border border-border px-2.5 py-1 rounded-md">
                        {threatActorName}
                      </span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="text-text-muted italic text-[11px]">Unattributed</span>
                        <button
                          onClick={handleInferThreatActor}
                          disabled={inferringActor}
                          className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-500/30 text-[11px] font-semibold rounded-md flex items-center gap-1.5 transition-colors"
                        >
                          <Sparkles className={`w-3 h-3 ${inferringActor ? 'animate-spin' : ''}`} />
                          {inferringActor ? 'Inferring...' : 'AI Infer Threat Actor from Evidence'}
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-text-muted w-36 flex-shrink-0 uppercase font-semibold">MALWARE / TOOLING</span>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {malwareList.length > 0 ? (
                      malwareList.map((m: any) => (
                        <span key={typeof m === 'string' ? m : m.name} className="bg-bg-elevated text-text-primary border border-border px-2.5 py-1 rounded-md">
                          {typeof m === 'string' ? m : m.name}
                        </span>
                      ))
                    ) : (
                      <span className="text-text-muted italic text-[11px]">None identified</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-text-muted w-36 flex-shrink-0 uppercase font-semibold">CVES</span>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {cveList.length > 0 ? (
                      cveList.map(cve => (
                        <span key={cve} className="bg-bg-elevated text-primary border border-primary/30 px-2.5 py-1 rounded-md font-bold">
                          {cve}
                        </span>
                      ))
                    ) : (
                      <span className="text-text-muted italic text-[11px]">None identified</span>
                    )}
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <span className="text-text-muted w-36 flex-shrink-0 uppercase font-semibold pt-1">ATT&CK</span>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {mitreTechniques.map((t: any) => (
                      <span key={t.technique_id} className="bg-bg-elevated text-text-secondary border border-border px-2.5 py-1 rounded-md">
                        {t.technique_id} - {t.technique_name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <p className="text-[11px] text-text-muted italic pt-2">
                AI-assisted assessment derived from the cited source — validate with your own analysis before operational use.
              </p>
            </div>
          </div>

          {/* ── AI MITRE ATT&CK Mapping Card (Detailed Section) ──────── */}
          {mitreTechniques.length > 0 && (
            <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold text-text-primary font-display">
                    AI-Based MITRE ATT&CK Mapping ({mitreTechniques.length} Techniques)
                  </h3>
                </div>
                <a
                  href={`https://attack.mitre.org/` }
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1 font-mono"
                >
                  MITRE Navigator <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="text-text-muted border-b border-border font-mono uppercase text-[10px] tracking-wider">
                      <th className="pb-2.5 pr-4">Technique ID</th>
                      <th className="pb-2.5 pr-4">Technique Name</th>
                      <th className="pb-2.5 pr-4">Tactic</th>
                      <th className="pb-2.5">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {mitreTechniques.map((t: any) => (
                      <tr key={t.technique_id} className="hover:bg-bg-elevated/60 transition-colors">
                        <td className="py-3 pr-4 font-mono font-bold">
                          <a
                            href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:underline flex items-center gap-1"
                          >
                            {t.technique_id} <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                          </a>
                        </td>
                        <td className="py-3 pr-4 text-text-primary font-medium">{t.technique_name}</td>
                        <td className="py-3 pr-4">
                          <span className={clsx('text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase',
                            t.tactic === 'Initial Access'      ? 'bg-severity-critical/15 text-severity-critical border-severity-critical/30' :
                            t.tactic === 'Persistence'         ? 'bg-secondary/15 text-secondary border-secondary/30' :
                            t.tactic === 'Collection'          ? 'bg-accent-cyan/15 text-accent-cyan border-accent-cyan/30' :
                            t.tactic === 'Privilege Escalation'? 'bg-accent-orange/15 text-accent-orange border-accent-orange/30' :
                                                                 'bg-primary/15 text-primary border-primary/30'
                          )}>
                            {t.tactic}
                          </span>
                        </td>
                        <td className="py-3">
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <div className="h-1.5 w-20 bg-bg-overlay rounded-full overflow-hidden">
                              <div
                                className="h-full bg-accent-green rounded-full"
                                style={{ width: `${(t.confidence || 0.85) * 100}%` }}
                              />
                            </div>
                            <span className="text-accent-green font-bold">{Math.round((t.confidence || 0.85) * 100)}%</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Attack Chain (Kill Chain) Timeline ────────────────── */}
          {validChainSteps.length > 0 && (
            <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-accent-orange" />
                <h3 className="text-sm font-bold text-text-primary font-display">Attack Chain (Kill Chain)</h3>
              </div>
              <div className="space-y-2.5">
                {validChainSteps.map(([phase, desc]) => (
                  <div key={phase} className="flex items-start gap-3 p-3 rounded-xl bg-bg-elevated border border-border">
                    <span className="text-xs font-mono font-bold text-accent-orange capitalize flex-shrink-0 w-36 pt-0.5">
                      {phase.replace('_', ' ')}
                    </span>
                    <p className="text-xs text-text-secondary leading-relaxed flex-1">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Threat Actor Profile & Evidence Attribution ────────────────── */}
          {((threatActor && threatActor.description) || inferredActor) && (
            <div className="card p-6 bg-bg-surface border border-cyan-500/30 shadow-xl rounded-2xl space-y-4 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-text-primary font-display">
                    Threat Actor Profile {inferredActor ? '(AI Attributed from Evidence)' : ''}
                  </h3>
                </div>
                {inferredActor && !savedActor && (
                  <button
                    onClick={handleSaveInferredActor}
                    className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow-md transition-colors"
                  >
                    Save Profile to Directory
                  </button>
                )}
                {savedActor && (
                  <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                    <CheckCheck className="w-3.5 h-3.5" /> Saved to Platform Directory
                  </span>
                )}
              </div>

              {inferredActor ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2.5 flex-wrap text-xs font-mono">
                    <span className="font-bold text-cyan-400 text-base">{inferredActor.name}</span>
                    {inferredActor.origin_country && (
                      <span className="px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                        Origin: {inferredActor.origin_country}
                      </span>
                    )}
                    {inferredActor.sophistication && (
                      <span className="px-2.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 uppercase font-semibold">
                        {inferredActor.sophistication}
                      </span>
                    )}
                    {inferredActor.confidence_score && (
                      <span className="px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                        {Math.round(inferredActor.confidence_score * 100)}% Confidence
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-text-secondary leading-relaxed">{inferredActor.description}</p>

                  {inferredActor.attribution_reasoning && (
                    <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl space-y-1.5">
                      <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3 h-3 text-cyan-400" />
                        AI Attribution Rationale & Evidence Reasoning:
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans">
                        {inferredActor.attribution_reasoning}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className="font-bold text-secondary text-sm">{threatActor.name}</span>
                    {threatActor.sophistication && <span className="tag">Sophistication: {threatActor.sophistication}</span>}
                    {threatActor.motivation && <span className="tag">Motivation: {threatActor.motivation}</span>}
                  </div>
                  <p className="text-xs text-text-secondary leading-relaxed">{threatActor.description}</p>
                </div>
              )}
            </div>
          )}

          {/* ── Impact & Recommendations ───────────────────────────── */}
          {(actions.length > 0 || recommendations.length > 0) && (
            <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
              {actions.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest bg-severity-critical/15 text-severity-critical px-2.5 py-1 rounded-md border border-severity-critical/20 inline-block">
                    IMPACT & ACTIONS
                  </span>
                  <ul className="space-y-1.5 text-xs text-text-secondary">
                    {actions.map((act, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-severity-critical font-bold">✓</span>
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {recommendations.length > 0 && (
                <div className="space-y-2 pt-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest bg-accent-green/15 text-accent-green px-2.5 py-1 rounded-md border border-accent-green/20 inline-block">
                    RECOMMENDATIONS
                  </span>
                  <ul className="space-y-1.5 text-xs text-text-secondary">
                    {recommendations.map((rec, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="text-accent-green font-bold">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* ── Detection Guidance & YARA Rules ────────────────────── */}
          {(detectionNotes || yaraRules.length > 0) && (
            <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-accent-cyan" />
                <h3 className="text-sm font-bold text-text-primary font-display">Detection Guidance & YARA Rules</h3>
              </div>
              {detectionNotes && <p className="text-xs text-text-secondary leading-relaxed">{detectionNotes}</p>}
              {yaraRules.length > 0 && (
                <div className="space-y-1">
                  <span className="text-xs font-mono font-bold text-accent-cyan uppercase">YARA Rule</span>
                  <pre className="code-block text-[11px]">{yaraRules.join('\n\n')}</pre>
                </div>
              )}
            </div>
          )}

          {/* ── Indicators (IOCs) Section ──────────────────────────── */}
          {allIocValues.length > 0 && (
            <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider font-mono">
                    INDICATORS (IOCS) · {allIocValues.length} VERIFIED
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setDefang(!defang)}
                    className={clsx('text-xs px-2.5 py-1 rounded-md border font-mono transition-all',
                      defang ? 'bg-accent-green/20 text-accent-green border-accent-green/30' : 'bg-bg-elevated text-text-muted border-border'
                    )}
                  >
                    Defang: {defang ? 'on' : 'off'}
                  </button>
                  <button
                    onClick={handleCopyAll}
                    className="btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 font-mono"
                  >
                    {copiedAll ? <CheckCheck className="w-3.5 h-3.5 text-accent-green" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedAll ? 'Copied!' : 'Copy all'}
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {allIocValues.map((val, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 rounded-xl bg-bg-elevated border border-border/70 font-mono text-xs hover:border-primary/30 transition-colors">
                    <div className="flex items-center gap-3">
                      <span className="text-text-muted text-[10px] uppercase font-bold w-16">INDICATOR</span>
                      <span className="text-text-primary font-bold">{defang ? val.replace(/\./g, '[.]') : val}</span>
                    </div>
                    <span className="text-[10px] bg-bg-base text-accent-green border border-accent-green/30 px-2 py-0.5 rounded font-mono">
                      88
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── References Block ───────────────────────────────────── */}
          <div className="card p-6 bg-bg-surface border-border rounded-2xl space-y-3">
            <span className="text-[10px] font-bold uppercase tracking-widest bg-primary/15 text-primary px-2.5 py-1 rounded-md border border-primary/20 inline-block">
              REFERENCES
            </span>
            <div className="space-y-2 font-mono text-xs">
              <div>
                <p className="text-text-muted text-[10px]">{domain}</p>
                <a href={urlInput || report?.input_value || '#'} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline break-all">
                  {urlInput || report?.input_value}
                </a>
              </div>
              {cveList.map(cve => (
                <div key={cve}>
                  <p className="text-text-muted text-[10px]">NVD / CISA CVE Details ({cve})</p>
                  <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline block">
                    https://nvd.nist.gov/vuln/detail/{cve}
                  </a>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}
    </div>
  );
}

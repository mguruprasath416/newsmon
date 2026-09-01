'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Flame,
  AlertTriangle,
  Globe,
  TrendingUp,
  TrendingDown,
  Minus,
  RefreshCw,
  Layers,
  ExternalLink,
  ShieldAlert,
  Clock,
  Building2,
  FileText,
  Search,
  ChevronRight,
  Info,
  CheckCircle2,
  X,
  Sparkles,
  Zap,
  Activity,
  Calendar,
} from 'lucide-react';
import { cyberpulseApi } from '@/lib/api/client';
import { clsx } from 'clsx';
import { formatDistanceToNow, format } from 'date-fns';

function CyberPulsePageContent() {
  const searchParams = useSearchParams();
  const urlEventId = searchParams?.get('event') || null;
  const urlQ = searchParams?.get('q') || searchParams?.get('search') || searchParams?.get('title') || '';

  const queryClient = useQueryClient();
  const [selectedEventId, setSelectedEventId] = useState<string | null>(urlEventId);
  const [activeTab, setActiveTab] = useState<'heatmap' | 'trending' | 'high_priority'>('heatmap');
  const [searchFilter, setSearchFilter] = useState(urlQ);
  const [minSourcesFilter, setMinSourcesFilter] = useState(2);
  const [timeframe, setTimeframe] = useState<'24h' | '7d' | 'month' | 'archive' | 'all'>('24h');
  const [archiveYear, setArchiveYear] = useState<number>(2026);
  const [archiveMonth, setArchiveMonth] = useState<number>(9);

  const queryParams = React.useMemo(() => {
    if (timeframe === 'archive') {
      return { timeframe: 'custom', year: archiveYear, month: archiveMonth };
    }
    return { timeframe };
  }, [timeframe, archiveYear, archiveMonth]);

  useEffect(() => {
    const eventParam = searchParams?.get('event');
    const qParam = searchParams?.get('q') || searchParams?.get('search') || searchParams?.get('title');
    if (eventParam) {
      setSelectedEventId(eventParam);
    }
    if (qParam) {
      setSearchFilter(qParam);
    }
  }, [searchParams]);

  // Fetch Heat Map Data (Daily, Weekly, Monthly, or Archive)
  const { data: heatMapData, isLoading: isHeatMapLoading, refetch: refetchHeatMap } = useQuery({
    queryKey: ['cyberpulse-heatmap', minSourcesFilter, queryParams],
    queryFn: () => cyberpulseApi.heatMap(minSourcesFilter, queryParams).then((res) => res.data),
    refetchInterval: 30000,
  });

  // Fetch Trending Events
  const { data: trendingData, isLoading: isTrendingLoading } = useQuery({
    queryKey: ['cyberpulse-trending', queryParams],
    queryFn: () => cyberpulseApi.trending(20, queryParams).then((res) => res.data),
    refetchInterval: 30000,
  });

  // Fetch High Priority Events (10+ sources)
  const { data: highPriorityData, isLoading: isHPLoading } = useQuery({
    queryKey: ['cyberpulse-high-priority', queryParams],
    queryFn: () => cyberpulseApi.highPriority(15, queryParams).then((res) => res.data),
    refetchInterval: 30000,
  });

  // Fetch Selected Event Details
  const { data: selectedEvent, isLoading: isSelectedLoading } = useQuery({
    queryKey: ['cyberpulse-event', selectedEventId],
    queryFn: () => (selectedEventId ? cyberpulseApi.get(selectedEventId).then((res) => res.data) : null),
    enabled: !!selectedEventId,
  });

  // Fetch Selected Event Articles
  const { data: eventArticlesData } = useQuery({
    queryKey: ['cyberpulse-articles', selectedEventId],
    queryFn: () => (selectedEventId ? cyberpulseApi.articles(selectedEventId, 50).then((res) => res.data) : null),
    enabled: !!selectedEventId,
  });

  // Recalculate Mutation
  const recalculateMutation = useMutation({
    mutationFn: () => cyberpulseApi.recalculate(72),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cyberpulse-heatmap'] });
      queryClient.invalidateQueries({ queryKey: ['cyberpulse-trending'] });
      queryClient.invalidateQueries({ queryKey: ['cyberpulse-high-priority'] });
    },
  });

  const allEvents = heatMapData?.events || [];
  const highPriorityEvents = highPriorityData?.high_priority_events || [];
  const trendingEvents = trendingData?.trending_events || [];

  // Auto-select event if search parameter was provided in the URL
  useEffect(() => {
    if (!selectedEventId && urlQ && allEvents.length > 0) {
      const qLower = urlQ.toLowerCase();
      const match = allEvents.find((e: any) =>
        (e.title || '').toLowerCase().includes(qLower) ||
        (e.target_company || '').toLowerCase().includes(qLower)
      );
      if (match) {
        setSelectedEventId(match.event_id);
      }
    }
  }, [urlQ, allEvents, selectedEventId]);

  const displayedEvents =
    activeTab === 'high_priority'
      ? highPriorityEvents
      : activeTab === 'trending'
      ? trendingEvents
      : allEvents;

  const filteredEvents = displayedEvents.filter((ev: any) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return (
      (ev.title || '').toLowerCase().includes(q) ||
      (ev.target_company || '').toLowerCase().includes(q) ||
      (ev.incident_type || '').toLowerCase().includes(q) ||
      (ev.unique_source_names || []).some((s: string) => s.toLowerCase().includes(q))
    );
  });

  const activeEvent =
    selectedEvent ||
    displayedEvents.find((e: any) => e.event_id === selectedEventId) ||
    allEvents.find((e: any) => e.event_id === selectedEventId) ||
    trendingEvents.find((e: any) => e.event_id === selectedEventId) ||
    highPriorityEvents.find((e: any) => e.event_id === selectedEventId);

  return (
    <div className="flex-1 space-y-6 p-6 md:p-8 max-w-[1600px] mx-auto">
      {/* ── Page Header ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/60 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-red-500/20 to-orange-500/10 border border-red-500/30 shadow-glow-sm">
              <Flame className="w-6 h-6 text-red-400 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold tracking-tight text-text-primary">
                  CyberPulse™
                </h1>
                <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-red-500/15 text-red-400 border border-red-500/30">
                  Viral Heat Map
                </span>
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-primary/10 text-primary border border-primary/20">
                  70+ Feeds Monitored
                </span>
              </div>
              <p className="text-xs md:text-sm text-text-muted mt-1">
                Real-time cross-source event correlation detecting viral cyber news and trending security incidents.
              </p>
            </div>
          </div>
        </div>

        {/* Header Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => recalculateMutation.mutate()}
            disabled={recalculateMutation.isPending}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-surface border border-border hover:bg-surface-hover transition-all text-text-secondary disabled:opacity-50"
            title="Scan recent articles and recalculate cross-source event clusters"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5', recalculateMutation.isPending && 'animate-spin')} />
            {recalculateMutation.isPending ? 'Recalculating...' : 'Recalculate Heat'}
          </button>
        </div>
      </div>

      {/* ── High Priority Alert Banner (When >= 10 sources report event) ─────── */}
      {highPriorityEvents.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-red-500/40 bg-gradient-to-r from-red-950/40 via-surface to-red-950/20 p-4 shadow-glow-sm"
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="p-2 rounded-lg bg-red-500/20 border border-red-500/40 flex-shrink-0 mt-0.5">
                <ShieldAlert className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-red-400">
                    🚨 High Priority CyberPulse Alert ({highPriorityEvents.length} Active)
                  </span>
                  <span className="px-1.5 py-0.2 text-[10px] font-bold rounded bg-red-500/20 text-red-300">
                    10+ Sources Threshold Crossed
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-text-primary mt-1 line-clamp-1">
                  {highPriorityEvents[0].title}
                </h3>
                <p className="text-xs text-text-muted mt-0.5">
                  Reported by <strong className="text-text-primary">{highPriorityEvents[0].source_count} independent sources</strong> across{' '}
                  <strong className="text-text-primary">{highPriorityEvents[0].article_count} total articles</strong>. Dispatched to Microsoft Teams.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 flex-shrink-0">
              <button
                onClick={() => setSelectedEventId(highPriorityEvents[0].event_id)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-500 hover:bg-red-600 text-white transition-all shadow-glow-sm flex items-center gap-1.5"
              >
                <span>Investigate Event</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Key Metrics Overview ────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-muted">Viral Events (≥{minSourcesFilter} Sources)</span>
            <Flame className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-text-primary mt-2">
            {allEvents.length}
          </div>
          <span className="text-[11px] text-text-muted">On active CyberPulse Heat Map</span>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-muted">High Heat Priority (≥10)</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 mt-2">
            {highPriorityEvents.length}
          </div>
          <span className="text-[11px] text-text-muted">Triggered Teams alerts</span>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-muted">Min Source Threshold</span>
            <Globe className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-primary mt-2">
            {minSourcesFilter} Sources
          </div>
          <span className="text-[11px] text-text-muted">Configurable correlation limit</span>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-text-muted">Correlation Window</span>
            <Clock className="w-4 h-4 text-secondary" />
          </div>
          <div className="text-2xl font-bold text-text-primary mt-2">
            72 Hours
          </div>
          <span className="text-[11px] text-text-muted">Temporal decay radius</span>
        </div>
      </div>

      {/* ── Time Scope Filter Toolbar ────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-2xl bg-surface border border-border">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs font-bold uppercase tracking-wider text-text-muted font-mono flex items-center gap-1.5 pl-1 pr-1">
            <Clock className="w-3.5 h-3.5 text-primary" /> Scope:
          </span>

          <button
            onClick={() => setTimeframe('24h')}
            className={clsx(
              'px-3 py-1.5 text-xs font-semibold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              timeframe === '24h'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Today (Daily Pulse)</span>
          </button>

          <button
            onClick={() => setTimeframe('7d')}
            className={clsx(
              'px-3 py-1.5 text-xs font-semibold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              timeframe === '7d'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Clock className="w-3.5 h-3.5 text-blue-400" />
            <span>Past 7 Days</span>
          </button>

          <button
            onClick={() => setTimeframe('month')}
            className={clsx(
              'px-3 py-1.5 text-xs font-semibold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              timeframe === 'month'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Calendar className="w-3.5 h-3.5 text-emerald-400" />
            <span>This Month</span>
          </button>

          <button
            onClick={() => setTimeframe('archive')}
            className={clsx(
              'px-3 py-1.5 text-xs font-semibold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              timeframe === 'archive'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span>Month Archive</span>
          </button>

          <button
            onClick={() => setTimeframe('all')}
            className={clsx(
              'px-3 py-1.5 text-xs font-semibold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer',
              timeframe === 'all'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Globe className="w-3.5 h-3.5 text-accent-cyan" />
            <span>All Time</span>
          </button>
        </div>

        {/* Month Picker Dropdown */}
        {timeframe === 'archive' && (
          <div className="flex items-center gap-2 bg-surface-hover px-3 py-1.5 rounded-xl border border-primary/30 animate-fade-in">
            <span className="text-[11px] text-text-muted font-medium">Select Month:</span>
            <select
              value={`${archiveYear}-${archiveMonth}`}
              onChange={(e) => {
                const [y, m] = e.target.value.split('-').map(Number);
                setArchiveYear(y);
                setArchiveMonth(m);
              }}
              className="text-xs font-semibold bg-surface text-text-primary border border-border rounded-lg px-2 py-1 outline-none focus:border-primary cursor-pointer"
            >
              <option value="2026-9">September 2026</option>
              <option value="2026-8">August 2026</option>
              <option value="2026-7">July 2026</option>
              <option value="2026-6">June 2026</option>
              <option value="2026-5">May 2026</option>
              <option value="2026-4">April 2026</option>
              <option value="2026-3">March 2026</option>
              <option value="2026-2">February 2026</option>
              <option value="2026-1">January 2026</option>
            </select>
          </div>
        )}
      </div>

      {/* ── Tabs & Search Bar ────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-1 p-1 rounded-xl bg-surface border border-border w-fit">
          <button
            onClick={() => setActiveTab('heatmap')}
            className={clsx(
              'px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5',
              activeTab === 'heatmap'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Heat Map Matrix ({allEvents.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('trending')}
            className={clsx(
              'px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5',
              activeTab === 'trending'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <Flame className="w-3.5 h-3.5 text-orange-400" />
            <span>Trending Events ({trendingData?.count || 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('high_priority')}
            className={clsx(
              'px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5',
              activeTab === 'high_priority'
                ? 'bg-primary text-white shadow-glow-sm'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
            )}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>High Priority ({highPriorityEvents.length})</span>
          </button>
        </div>

        {/* Filter & Search */}
        <div className="flex items-center gap-2">
          {/* Quick Source Filter Pills */}
          <div className="flex items-center gap-1 bg-surface border border-border p-1 rounded-lg">
            <span className="text-[10px] text-text-muted px-1 font-medium">Min:</span>
            {[2, 3, 5, 10].map((num) => (
              <button
                key={num}
                onClick={() => setMinSourcesFilter(num)}
                className={clsx(
                  'px-2 py-0.5 text-[11px] font-semibold rounded transition-all',
                  minSourcesFilter === num
                    ? 'bg-primary text-white'
                    : 'text-text-muted hover:text-text-primary hover:bg-surface-hover'
                )}
              >
                {num}+
              </button>
            ))}
          </div>

          <div className="relative flex-1 sm:w-56">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
            <input
              type="text"
              placeholder="Filter by title, company, vector..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-surface border border-border text-text-primary placeholder:text-text-muted focus:outline-none focus:border-primary transition-all"
            />
          </div>
        </div>
      </div>

      {/* ── Main View Content ────────────────────────────────────────────────── */}
      {isHeatMapLoading ? (
        <div className="flex flex-col items-center justify-center min-h-[350px] rounded-xl bg-surface border border-border">
          <RefreshCw className="w-8 h-8 text-primary animate-spin mb-3" />
          <p className="text-xs text-text-muted">Correlating viral cyber news events across 70+ feeds...</p>
        </div>
      ) : filteredEvents.length === 0 ? (
        <div className="flex flex-col items-center justify-center min-h-[350px] rounded-xl bg-surface border border-border p-8 text-center">
          <div className="w-12 h-12 rounded-2xl bg-surface-hover flex items-center justify-center mb-3">
            <Flame className="w-6 h-6 text-text-muted" />
          </div>
          <h3 className="text-base font-semibold text-text-primary">No Viral Events Detected</h3>
          <p className="text-xs text-text-muted max-w-md mt-1">
            CyberPulse requires at least <strong>5 independent configured sources</strong> to discuss the exact same news event before creating a heat map entry.
          </p>
          <button
            onClick={() => recalculateMutation.mutate()}
            className="mt-4 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-primary hover:bg-primary/90 text-white transition-all"
          >
            Run Correlation Sweep
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredEvents.map((event: any) => {
            const heat = event.heat_score || 0;
            const isSevere = heat >= 80;
            const isHigh = heat >= 60 && heat < 80;
            const isMedium = heat >= 40 && heat < 60;

            const heatBadgeColor = isSevere
              ? 'bg-red-500/20 text-red-400 border-red-500/30'
              : isHigh
              ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
              : isMedium
              ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
              : 'bg-green-500/20 text-green-400 border-green-500/30';

            const trendIcon =
              event.trend === 'increasing' ? (
                <TrendingUp className="w-3.5 h-3.5 text-red-400" />
              ) : event.trend === 'decreasing' ? (
                <TrendingDown className="w-3.5 h-3.5 text-green-400" />
              ) : (
                <Minus className="w-3.5 h-3.5 text-yellow-400" />
              );

            return (
              <motion.div
                key={event.event_id}
                whileHover={{ y: -2 }}
                onClick={() => setSelectedEventId(event.event_id)}
                className={clsx(
                  'cursor-pointer rounded-xl border p-4 transition-all relative flex flex-col justify-between',
                  selectedEventId === event.event_id
                    ? 'border-primary bg-surface shadow-glow-primary'
                    : 'border-border bg-surface hover:border-border/80 hover:bg-surface-hover'
                )}
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-center justify-between gap-2 mb-2.5">
                    <span className={clsx('px-2 py-0.5 text-[11px] font-bold rounded-md border', heatBadgeColor)}>
                      🔥 {heat}/100 HEAT
                    </span>
                    <div className="flex items-center gap-1.5 text-xs text-text-muted">
                      {trendIcon}
                      <span className="capitalize">{event.trend || 'Stable'}</span>
                    </div>
                  </div>

                  {/* Title */}
                  <h3 className="text-sm font-semibold text-text-primary line-clamp-2 mb-2 leading-snug">
                    {event.title}
                  </h3>

                  {/* Metadata Chips */}
                  <div className="flex flex-wrap items-center gap-1.5 mb-3">
                    {event.target_company && event.target_company !== 'Not Specified' && (
                      <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-surface border border-border text-text-secondary flex items-center gap-1">
                        <Building2 className="w-2.5 h-2.5 text-text-muted" />
                        {event.target_company}
                      </span>
                    )}
                    {event.incident_type && (
                      <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-surface border border-border text-text-secondary">
                        {event.incident_type}
                      </span>
                    )}
                    {event.threat_actors && event.threat_actors.length > 0 && event.threat_actors[0] !== 'Unknown' ? (
                      <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-red-500/10 border border-red-500/20 text-red-400">
                        {event.threat_actors[0]}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-[10px] font-medium rounded bg-surface-hover/80 border border-border text-text-muted">
                        Unattributed
                      </span>
                    )}
                  </div>
                </div>

                {/* Footer Metrics */}
                <div className="pt-3 border-t border-border/50 flex items-center justify-between text-xs text-text-muted">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1 text-text-primary font-medium">
                      <Globe className="w-3.5 h-3.5 text-primary" />
                      {event.source_count} Sources
                    </span>
                    <span className="flex items-center gap-1">
                      <FileText className="w-3.5 h-3.5 text-text-muted" />
                      {event.article_count} Articles
                    </span>
                  </div>

                  <span className="text-[10px] text-text-muted font-mono flex items-center gap-1">
                    <Calendar className="w-3 h-3 text-text-muted" />
                    {event.last_detected_at ? formatDistanceToNow(new Date(event.last_detected_at), { addSuffix: true }) : 'Recent'}
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}

      {/* ── Event Detail Drawer / Modal ─────────────────────────────────────── */}
      <AnimatePresence>
        {selectedEventId && activeEvent && (
          <div
            onClick={(e) => {
              if (e.target === e.currentTarget) setSelectedEventId(null);
            }}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end"
          >
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="w-full max-w-2xl bg-surface border-l border-border h-full overflow-y-auto flex flex-col shadow-2xl"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-border sticky top-0 bg-surface/95 backdrop-blur-md z-10 flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="px-2 py-0.5 text-xs font-bold rounded-md bg-red-500/20 text-red-400 border border-red-500/30">
                      🔥 {activeEvent.heat_score}/100 HEAT SCORE
                    </span>
                    <span className="px-2 py-0.5 text-xs font-medium rounded-md bg-surface-hover border border-border text-text-secondary uppercase">
                      {activeEvent.status?.replace('_', ' ') || 'ACTIVE EVENT'}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-text-primary leading-tight">
                    {activeEvent.title}
                  </h2>
                </div>

                <button
                  onClick={() => setSelectedEventId(null)}
                  className="p-1.5 rounded-lg hover:bg-surface-hover text-text-muted hover:text-text-primary transition-all"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="p-6 space-y-6 flex-1">
                {/* Metrics Quad Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-surface-hover/50 border border-border">
                  <div>
                    <span className="text-[11px] text-text-muted uppercase tracking-wider block">Unique Sources</span>
                    <span className="text-xl font-bold text-primary">{activeEvent.source_count}</span>
                    <span className="text-[10px] text-text-muted block">Independent feeds</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-text-muted uppercase tracking-wider block">Total Reports</span>
                    <span className="text-xl font-bold text-text-primary">{activeEvent.article_count}</span>
                    <span className="text-[10px] text-text-muted block">Correlated articles</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-text-muted uppercase tracking-wider block">Trend Status</span>
                    <span className="text-sm font-bold text-orange-400 capitalize block mt-1">
                      {activeEvent.trend === 'increasing' ? '↑ Increasing' : '→ Stable'}
                    </span>
                    <span className="text-[10px] text-text-muted block">Velocity score: {activeEvent.velocity_score || 15}</span>
                  </div>
                  <div>
                    <span className="text-[11px] text-text-muted uppercase tracking-wider block">Target Geography</span>
                    <span className="text-sm font-semibold text-text-primary block mt-1">
                      {activeEvent.target_country || 'Global'}
                    </span>
                    <span className="text-[10px] text-text-muted block">{activeEvent.target_company || 'Multiple Orgs'}</span>
                  </div>
                </div>

                {/* Analyst Explanation Card */}
                <div className="p-4 rounded-xl bg-primary/5 border border-primary/20 space-y-2">
                  <div className="flex items-center gap-2 text-primary font-semibold text-xs">
                    <Sparkles className="w-4 h-4" />
                    <span>Analyst Correlation Explanation</span>
                  </div>
                  <p className="text-xs text-text-secondary whitespace-pre-line leading-relaxed">
                    {activeEvent.explanation || `This CyberPulse viral event was correlated across ${activeEvent.source_count} independent threat intelligence sources.`}
                  </p>
                </div>

                {/* Independent Sources Pill List */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-text-muted mb-2.5 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-primary" />
                    <span>Independent Corroborating Sources ({activeEvent.unique_source_names?.length || activeEvent.source_count || 0})</span>
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {(activeEvent.unique_source_names || []).map((source: string, idx: number) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 text-xs font-medium rounded-lg bg-surface-hover border border-border text-text-primary flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3 h-3 text-green-400" />
                        {source}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Correlated Articles Feed */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-text-muted mb-2.5 flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-text-muted" />
                    <span>Correlated Original Articles ({eventArticlesData?.articles?.length || activeEvent.article_count || 0})</span>
                  </h4>
                  {isSelectedLoading && !eventArticlesData ? (
                    <div className="p-6 text-center text-xs text-text-muted">
                      <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-primary" />
                      Loading correlated articles...
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {(eventArticlesData?.articles || []).map((art: any) => (
                        <div
                          key={art._id}
                          className="p-3 rounded-lg bg-surface-hover/60 border border-border hover:border-primary/40 transition-all flex flex-col justify-between gap-2"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <Link href={`/feed/${art._id || art.id}`}>
                              <h5 className="text-xs font-semibold text-text-primary hover:text-primary transition-colors leading-snug cursor-pointer">
                                {art.title}
                              </h5>
                            </Link>
                            {art.url && !art.url.startsWith('/') && !art.url.includes('localhost') && (
                              <a
                                href={art.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-text-muted hover:text-primary transition-colors flex-shrink-0 p-0.5"
                                title="Original Source Website"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            )}
                          </div>
                          <div className="flex items-center justify-between text-[11px] text-text-muted">
                            <span className="text-primary font-medium">{art.source_name}</span>
                            <span>
                              {art.published_at ? new Date(art.published_at).toLocaleString() : 'Recent'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function CyberPulsePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-xs text-text-muted">Loading CyberPulse threat map...</div>}>
      <CyberPulsePageContent />
    </Suspense>
  );
}

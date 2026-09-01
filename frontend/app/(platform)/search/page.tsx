'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { useMutation, useQuery } from '@tanstack/react-query';
import { searchApi } from '@/lib/api/client';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Database, Users, Bug, AlertTriangle, Loader2, X } from 'lucide-react';
import Link from 'next/link';
import { clsx } from 'clsx';

const ENTITY_TYPES = [
  { value: 'articles',      label: 'Articles',       icon: Database },
  { value: 'threat_actors', label: 'Threat Actors',  icon: Users },
  { value: 'malware',       label: 'Malware',        icon: Bug },
  { value: 'kev',           label: 'KEV',            icon: AlertTriangle },
];

function SearchPageContent() {
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [query, setQuery] = useState(initialQuery);
  const [types, setTypes] = useState(['articles', 'threat_actors', 'malware', 'kev']);
  const [submitted, setSubmitted] = useState(initialQuery);

  const { data, isPending: isLoading, mutate } = useMutation({
    mutationFn: (searchQuery?: string) =>
      searchApi.search({ query: searchQuery || submitted, types: types.join(',') }).then(r => r.data),
  });

  useEffect(() => {
    const q = searchParams.get('q');
    if (q && q.trim()) {
      setQuery(q);
      setSubmitted(q);
      mutate(q);
    }
  }, [searchParams]);

  const { data: suggestions } = useQuery({
    queryKey: ['suggest', query],
    queryFn: () => searchApi.suggest(query).then(r => r.data),
    enabled: query.length >= 3,
    staleTime: 5000,
  });

  const handleSearch = () => {
    if (!query.trim()) return;
    setSubmitted(query);
    mutate(query);
  };

  const toggleType = (type: string) => {
    setTypes(prev => prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]);
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Search bar */}
      <div className="space-y-3">
        <div className="relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-text-muted" />
          <input
            className="w-full pl-12 pr-4 py-4 bg-bg-surface border border-border rounded-xl text-text-primary placeholder:text-text-muted text-base focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all duration-200"
            placeholder="Search threats, IOCs, CVEs, malware, actors..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            autoFocus
          />
          {query && (
            <button onClick={() => setQuery('')} className="absolute right-4 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Type filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-text-muted">Search in:</span>
          {ENTITY_TYPES.map(({ value, label, icon: Icon }) => (
            <button
              key={value}
              onClick={() => toggleType(value)}
              className={clsx(
                'flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all duration-200',
                types.includes(value)
                  ? 'bg-primary/15 text-primary border-primary/30'
                  : 'bg-bg-elevated text-text-muted border-border hover:border-primary/20'
              )}
            >
              <Icon className="w-3 h-3" />
              {label}
            </button>
          ))}
          <button
            onClick={handleSearch}
            disabled={!query.trim() || isLoading}
            className="ml-auto btn-primary flex items-center gap-2 text-sm"
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
        </div>

        {/* Suggestions */}
        <AnimatePresence>
          {suggestions?.suggestions?.length > 0 && !submitted && (
            <motion.div initial={{ opacity: 0, y: -5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="card p-3 space-y-1">
              {suggestions.suggestions.map((s: any, i: number) => (
                <button key={i} onClick={() => { setQuery(s.value); setSubmitted(s.value); mutate(s.value); }}
                  className="w-full text-left flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-bg-elevated text-sm text-text-secondary transition-colors">
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium border',
                    s.type === 'threat_actor' ? 'bg-secondary/10 text-secondary border-secondary/20' :
                    s.type === 'malware'      ? 'bg-accent-orange/10 text-accent-orange border-accent-orange/20' :
                                                'bg-severity-critical/10 text-severity-critical border-severity-critical/20'
                  )}>
                    {s.type.replace('_', ' ')}
                  </span>
                  {s.value}
                  {s.in_kev && <span className="ml-auto text-[10px] text-severity-critical font-bold">KEV</span>}
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Results */}
      {data && (
        <div className="space-y-6 animate-fade-in">
          {/* Articles */}
          {data.results?.articles?.data?.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-3">
                <Database className="w-4 h-4 text-primary" />
                <h2 className="font-semibold text-text-primary">Articles</h2>
                <span className="tag">{data.results.articles.total}</span>
              </div>
              <div className="space-y-2">
                {data.results.articles.data.slice(0, 5).map((a: any) => (
                  <Link key={a.id} href={`/feed/${a.id}`}>
                    <div className="card p-4 hover:border-primary/25 transition-all cursor-pointer">
                      <p className="text-sm font-medium text-text-primary hover:text-primary mb-1">{a.title}</p>
                      <p className="text-xs text-text-muted">{a.source_name} · {a.severity}</p>
                      {a.highlight?.summary && (
                        <p className="text-xs text-text-muted mt-1" dangerouslySetInnerHTML={{ __html: a.highlight.summary[0] }} />
                      )}
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Threat Actors */}
          {data.results?.threat_actors?.data?.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-3">
                <Users className="w-4 h-4 text-secondary" />
                <h2 className="font-semibold text-text-primary">Threat Actors</h2>
                <span className="tag">{data.results.threat_actors.total}</span>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {data.results.threat_actors.data.slice(0, 4).map((a: any) => (
                  <Link key={a.id} href={`/threat-actors/${a.id}`}>
                    <div className="card p-4 hover:border-secondary/25 transition-all cursor-pointer">
                      <p className="font-medium text-text-primary text-sm">{a.name}</p>
                      <p className="text-xs text-text-muted mt-0.5">{a.type} · {a.origin_country || 'Unknown origin'}</p>
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* KEV */}
          {data.results?.kev?.data?.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-severity-critical" />
                <h2 className="font-semibold text-text-primary">KEV Matches</h2>
                <span className="tag">{data.results.kev.total}</span>
              </div>
              <div className="space-y-2">
                {data.results.kev.data.slice(0, 5).map((k: any) => (
                  <div key={k.cve_id} className="card p-4">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-primary font-bold">{k.cve_id}</span>
                      {k.known_ransomware && <span className="text-[10px] badge-critical px-1.5 py-0.5 rounded">Ransomware</span>}
                    </div>
                    <p className="text-xs text-text-muted mt-1">{k.vendor} · {k.product}</p>
                    <p className="text-xs text-text-secondary mt-0.5">{k.vulnerability_name}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* No results */}
          {Object.values(data.results).every((r: any) => !r?.data?.length) && (
            <div className="text-center py-16">
              <Search className="w-12 h-12 text-text-muted mx-auto mb-4" />
              <p className="text-text-secondary font-medium">No results for "{submitted}"</p>
              <p className="text-sm text-text-muted mt-1">Try broader search terms or different entity types</p>
            </div>
          )}
        </div>
      )}

      {!data && !isLoading && (
        <div className="text-center py-20">
          <Search className="w-16 h-16 text-text-muted mx-auto mb-4 opacity-30" />
          <p className="text-text-muted">Search across all intelligence entities</p>
          <p className="text-sm text-text-disabled mt-1">Powered by Elasticsearch + MongoDB</p>
        </div>
      )}
    </div>
  );
}

export default function SearchPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-xs text-text-muted">Loading search...</div>}>
      <SearchPageContent />
    </Suspense>
  );
}

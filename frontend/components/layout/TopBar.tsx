'use client';

import { usePathname } from 'next/navigation';
import { Search } from 'lucide-react';
import { useUIStore } from '@/lib/stores/store';
import { useEffect } from 'react';

const PAGE_TITLES: Record<string, { title: string; description: string }> = {
  '/dashboard': { title: 'Dashboard',        description: 'Live cyber threat news stream & intelligence overview' },
  '/news':      { title: 'News Hub',         description: 'Categorized Cyber News (Breach, Vulnerability, Ransomware, APT)' },
  '/feed':      { title: 'Intel Feed',       description: 'Real-time cybersecurity news and vendor research feeds' },
  '/clusters':  { title: 'Manage Clusters',  description: 'Threat news clusters & custom discovery rules' },
  '/lens':      { title: 'Advisory Lens',     description: 'AI-powered threat article & advisory analysis' },
  '/search':    { title: 'Search',            description: 'Search articles, CVEs, and advisories' },
  '/kev':       { title: 'CISA KEV Catalog',  description: 'Known Exploited Vulnerabilities catalog' },
  '/sources':   { title: 'Monitored Sources', description: '33+ active RSS feeds, vendor blogs, and CERT advisories' },
};

export function TopBar() {
  const pathname = usePathname();
  const { openCommandPalette } = useUIStore();

  const pageKey = Object.keys(PAGE_TITLES).find(k => pathname.startsWith(k)) || '/dashboard';
  const { title, description } = PAGE_TITLES[pageKey] || { title: 'NewsMon', description: '' };

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        openCommandPalette();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [openCommandPalette]);

  const now = new Date().toLocaleDateString('en-US', {
    weekday: 'short', month: 'short', day: 'numeric', year: 'numeric'
  });

  return (
    <header className="h-16 bg-bg-surface border-b border-border flex items-center justify-between px-6 flex-shrink-0">
      {/* Page Info */}
      <div className="flex flex-col">
        <h1 className="text-base font-semibold text-text-primary font-display">{title}</h1>
        <p className="text-xs text-text-muted">{description}</p>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Date */}
        <span className="text-xs text-text-muted hidden lg:block">{now}</span>

        {/* Search shortcut */}
        <button
          onClick={openCommandPalette}
          className="flex items-center gap-2 px-3 py-1.5 bg-bg-elevated border border-border rounded-lg text-text-muted text-xs hover:border-primary/40 hover:text-text-secondary transition-all duration-200"
        >
          <Search className="w-3.5 h-3.5" />
          <span className="hidden sm:block">Search articles...</span>
          <kbd className="hidden sm:flex items-center gap-0.5 bg-bg-base px-1.5 py-0.5 rounded text-[10px] border border-border">
            <span>⌘</span><span>K</span>
          </kbd>
        </button>
      </div>
    </header>
  );
}

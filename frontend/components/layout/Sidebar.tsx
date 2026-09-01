'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { useUIStore } from '@/lib/stores/store';
import {
  LayoutDashboard, Rss, Sparkles, AlertTriangle, Search,
  ChevronLeft, ChevronRight, BookOpen, Globe, Shield, Users, Bell, Layers, Flame
} from 'lucide-react';
import { clsx } from 'clsx';

const NAV_SECTIONS = [
  {
    label: 'News & Intelligence',
    items: [
      { href: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard' },
      { href: '/cyberpulse',  icon: Flame,           label: 'CyberPulse', badge: 'Viral' },
      { href: '/feed',        icon: Rss,             label: 'Intel Feed', badge: 'Live' },
      { href: '/clusters',    icon: Layers,          label: 'Manage Clusters' },
      { href: '/lens',        icon: Sparkles,        label: 'Advisory Lens', badge: 'AI' },
      { href: '/search',      icon: Search,          label: 'Search' },
    ],
  },
  {
    label: 'Feeds & Advisories',
    items: [
      { href: '/kev',         icon: AlertTriangle,   label: 'CISA KEV Catalog' },
      { href: '/sources',     icon: Globe,           label: 'Monitored Sources' },
    ],
  },
];




export function Sidebar() {
  const pathname = usePathname();
  const { sidebarCollapsed, toggleSidebar } = useUIStore();

  const isActive = (href: string) =>
    pathname === href || (href !== '/dashboard' && pathname.startsWith(href));

  return (
    <motion.aside
      animate={{ width: sidebarCollapsed ? 64 : 240 }}
      transition={{ duration: 0.25, ease: 'easeInOut' }}
      className="relative h-screen flex flex-col bg-bg-surface border-r border-border flex-shrink-0 overflow-hidden"
    >
      {/* Logo */}
      <div className={clsx(
        'flex items-center gap-3 px-4 h-16 border-b border-border flex-shrink-0',
        sidebarCollapsed && 'justify-center px-0'
      )}>
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-secondary flex items-center justify-center flex-shrink-0 shadow-glow-primary">
          <Shield className="w-4 h-4 text-white" />
        </div>
        <AnimatePresence>
          {!sidebarCollapsed && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.15 }}
              className="flex flex-col"
            >
              <span className="text-sm font-bold text-text-primary font-display tracking-tight">NewsMon</span>
              <span className="text-[10px] text-text-muted leading-none">Cyber Threat News Feed</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 scrollbar-none">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="mb-2">
            {!sidebarCollapsed && (
              <p className="section-title px-4 pt-3 pb-2 text-[10px]">{section.label}</p>
            )}
            <ul className="space-y-0.5 px-2">
              {section.items.map(({ href, icon: Icon, label, badge }) => {
                const active = isActive(href);
                return (
                  <li key={href}>
                    <Link
                      href={href}
                      title={sidebarCollapsed ? label : undefined}
                      className={clsx(
                        'flex items-center gap-3 px-2.5 py-2 rounded-lg text-sm font-medium transition-all duration-200 group',
                        active
                          ? 'bg-primary/15 text-primary border border-primary/20'
                          : 'text-text-secondary hover:bg-primary/8 hover:text-text-primary',
                        sidebarCollapsed && 'justify-center px-0 w-full'
                      )}
                    >
                      <Icon className={clsx('w-4 h-4 flex-shrink-0', active ? 'text-primary' : 'text-text-muted group-hover:text-text-secondary')} />
                      <AnimatePresence>
                        {!sidebarCollapsed && (
                          <motion.span
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex-1 truncate"
                          >
                            {label}
                          </motion.span>
                        )}
                      </AnimatePresence>
                      {!sidebarCollapsed && badge && (
                        <span className={clsx(
                          'text-[9px] font-bold px-1.5 py-0.5 rounded-full',
                          badge === 'AI' ? 'bg-secondary/20 text-secondary border border-secondary/30' :
                          'bg-accent-green/20 text-accent-green border border-accent-green/30'
                        )}>
                          {badge}
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Collapse Toggle */}
      <div className="p-2 border-t border-border flex-shrink-0">
        <button
          onClick={toggleSidebar}
          className="w-full flex items-center justify-center p-2 rounded-lg text-text-muted hover:text-text-secondary hover:bg-bg-elevated transition-all duration-200"
        >
          {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : (
            <div className="flex items-center gap-2 w-full px-1">
              <ChevronLeft className="w-4 h-4" />
              <span className="text-xs">Collapse</span>
            </div>
          )}
        </button>
      </div>
    </motion.aside>
  );
}

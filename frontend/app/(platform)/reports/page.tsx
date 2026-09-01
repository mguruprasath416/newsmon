'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { reportsApi } from '@/lib/api/client';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { FileText, Download, Share2, Trash2, ExternalLink, Sparkles } from 'lucide-react';
import { format } from 'date-fns';
import Link from 'next/link';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [page, setPage] = useState(1);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['reports', { page }],
    queryFn: () => reportsApi.list({ page, page_size: 20 }).then(r => r.data),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportsApi.delete(id),
    onSuccess: () => {
      toast.success('Report deleted');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: () => toast.error('Failed to delete report'),
  });

  const reports = data?.data ?? [];
  const meta = data?.meta ?? {};

  const handleShare = async (id: string) => {
    try {
      const res = await reportsApi.share(id);
      const url = `${window.location.origin}/share/${res.data.share_token}`;
      navigator.clipboard.writeText(url);
      toast.success('Share URL copied to clipboard!');
    } catch {
      toast.error('Failed to share report');
    }
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-text-primary font-display">Intelligence Reports</h2>
          <p className="text-xs text-text-muted">Generated reports from Advisory Lens</p>
        </div>
        <Link href="/lens" className="btn-primary flex items-center gap-2 text-xs">
          <Sparkles className="w-3.5 h-3.5" />New Report
        </Link>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-text-muted text-left">
                <th className="px-4 py-3 font-medium">Report / Job ID</th>
                <th className="px-4 py-3 font-medium">Input Type</th>
                <th className="px-4 py-3 font-medium">TLP</th>
                <th className="px-4 py-3 font-medium">Date Created</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 5 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><div className="h-4 skeleton rounded" /></td>
                    ))}
                  </tr>
                ))
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-12 text-center text-text-muted">
                    <FileText className="w-8 h-8 text-text-muted mx-auto mb-2" />
                    No reports generated yet. Use <Link href="/lens" className="text-primary underline">Advisory Lens</Link> to create one.
                  </td>
                </tr>
              ) : reports.map((r: any) => (
                <tr key={r.id} className="hover:bg-bg-elevated transition-colors">
                  <td className="px-4 py-3">
                    <span className="font-mono text-primary font-medium">{r.job_id}</span>
                    {r.input_value && <p className="text-[10px] text-text-muted truncate max-w-64">{r.input_value}</p>}
                  </td>
                  <td className="px-4 py-3">
                    <span className="tag uppercase">{r.input_type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-accent-green/10 text-accent-green border border-accent-green/20 uppercase">
                      {r.tlp_level || 'WHITE'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-text-muted font-mono">
                    {r.created_at ? format(new Date(r.created_at), 'yyyy-MM-dd HH:mm') : '—'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => handleShare(r.id)} title="Share Link" className="text-text-muted hover:text-primary p-1">
                        <Share2 className="w-3.5 h-3.5" />
                      </button>
                      <a href={`/api/v1/reports/${r.id}/export?format=markdown`} download title="Download Markdown" className="text-text-muted hover:text-primary p-1">
                        <Download className="w-3.5 h-3.5" />
                      </a>
                      <button onClick={() => deleteMutation.mutate(r.id)} title="Delete" className="text-text-muted hover:text-severity-critical p-1">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

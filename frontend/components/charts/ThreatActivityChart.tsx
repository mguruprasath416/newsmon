'use client';

import ReactECharts from 'echarts-for-react';

interface Props {
  data: Record<string, Record<string, number>>;
}

export function ThreatActivityChart({ data }: Props) {
  const dates = Object.keys(data).sort();
  const severities = ['critical', 'high', 'medium', 'low', 'informational'];
  const colors = ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#2563eb'];

  const series = severities.map((sev, i) => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    type: 'bar',
    stack: 'total',
    data: dates.map(d => data[d]?.[sev] || 0),
    itemStyle: { color: colors[i] },
    emphasis: { focus: 'series' },
  }));

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: '#141822',
      borderColor: '#1e2840',
      textStyle: { color: '#f1f5f9', fontSize: 11 },
    },
    legend: {
      data: series.map(s => s.name),
      textStyle: { color: '#64748b', fontSize: 10 },
      top: 0,
    },
    grid: { left: 40, right: 10, bottom: 30, top: 30 },
    xAxis: {
      type: 'category',
      data: dates,
      axisLabel: { color: '#64748b', fontSize: 9, rotate: 30 },
      axisLine: { lineStyle: { color: '#1e2840' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', fontSize: 9 },
      splitLine: { lineStyle: { color: '#1e2840' } },
    },
    series,
  };

  return <ReactECharts option={option} style={{ height: 220 }} />;
}

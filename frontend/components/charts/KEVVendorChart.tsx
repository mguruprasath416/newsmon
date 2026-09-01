'use client';

import ReactECharts from 'echarts-for-react';

interface Props {
  data: { vendor: string; count: number }[];
}

export function KEVVendorChart({ data }: Props) {
  const sorted = [...data].sort((a, b) => b.count - a.count).slice(0, 12);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: '#141822',
      borderColor: '#1e2840',
      textStyle: { color: '#f1f5f9', fontSize: 11 },
      formatter: (params: any) => `${params[0].name}: <strong>${params[0].value}</strong> CVEs`,
    },
    grid: { left: 120, right: 30, bottom: 20, top: 10 },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', fontSize: 9 },
      splitLine: { lineStyle: { color: '#1e2840' } },
    },
    yAxis: {
      type: 'category',
      data: sorted.map(d => d.vendor).reverse(),
      axisLabel: { color: '#94a3b8', fontSize: 10 },
      axisLine: { lineStyle: { color: '#1e2840' } },
    },
    series: [{
      type: 'bar',
      data: sorted.map(d => d.count).reverse(),
      itemStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
          colorStops: [
            { offset: 0, color: '#4f7eff' },
            { offset: 1, color: '#7c5cfc' },
          ],
        },
        borderRadius: [0, 4, 4, 0],
      },
      emphasis: { itemStyle: { color: '#6b94ff' } },
    }],
  };

  return <ReactECharts option={option} style={{ height: 280 }} />;
}

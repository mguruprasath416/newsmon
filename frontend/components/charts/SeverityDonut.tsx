'use client';

import ReactECharts from 'echarts-for-react';

export function SeverityDonut({ data }: { data: Record<string, number> }) {
  const colorMap: Record<string, string> = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04',
    low: '#16a34a', informational: '#2563eb',
  };
  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    itemStyle: { color: colorMap[name] || '#64748b' },
  }));

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: '#141822',
      borderColor: '#1e2840',
      textStyle: { color: '#f1f5f9', fontSize: 11 },
    },
    legend: { show: false },
    series: [{
      type: 'pie',
      radius: ['55%', '80%'],
      data: chartData,
      label: { show: false },
      emphasis: { scale: true, scaleSize: 4 },
    }],
  };

  return <ReactECharts option={option} style={{ height: 160 }} />;
}

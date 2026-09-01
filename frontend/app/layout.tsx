import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Providers } from '@/components/providers';
import { Toaster } from 'react-hot-toast';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: {
    default: 'NewsMon — Enterprise Cyber Threat Intelligence',
    template: '%s | NewsMon',
  },
  description: 'Enterprise-grade Cyber Threat Intelligence Platform for SOC teams, threat analysts, and incident responders.',
  keywords: ['cyber threat intelligence', 'CTI', 'SOC', 'threat analysis', 'IOC', 'MITRE ATT&CK'],
  robots: 'noindex, nofollow',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Outfit:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className={`${inter.variable} bg-bg-base text-text-primary antialiased`}>
        <Providers>
          {children}
          <Toaster
            position="bottom-right"
            toastOptions={{
              style: {
                background: '#141822',
                color: '#f1f5f9',
                border: '1px solid #1e2840',
                borderRadius: '10px',
              },
            }}
          />
        </Providers>
      </body>
    </html>
  );
}

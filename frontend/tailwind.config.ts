import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
    },
    extend: {
      colors: {
        // ── Base surfaces ─────────────────────────────────────────────
        bg: {
          base:     "#080b12",
          surface:  "#0e1219",
          elevated: "#141822",
          overlay:  "#1c2130",
          subtle:   "#222840",
          input:    "#141822",
        },
        // ── Brand ─────────────────────────────────────────────────────
        primary: {
          DEFAULT:  "#4f7eff",
          hover:    "#6b94ff",
          muted:    "#4f7eff1a",
          subtle:   "#4f7eff0d",
        },
        secondary: {
          DEFAULT:  "#7c5cfc",
          hover:    "#9478ff",
          muted:    "#7c5cfc1a",
        },
        accent: {
          cyan:   "#00d4ff",
          green:  "#22d3a0",
          orange: "#ff8c42",
          pink:   "#ff5c8a",
        },
        // ── Severity ──────────────────────────────────────────────────
        severity: {
          critical: "#dc2626",
          high:     "#ea580c",
          medium:   "#ca8a04",
          low:      "#16a34a",
          info:     "#2563eb",
          unknown:  "#64748b",
        },
        // ── Text ──────────────────────────────────────────────────────
        text: {
          primary:   "#f1f5f9",
          secondary: "#94a3b8",
          muted:     "#64748b",
          disabled:  "#334155",
        },
        // ── Borders ───────────────────────────────────────────────────
        border: {
          DEFAULT: "#1e2840",
          subtle:  "#151d2e",
          strong:  "#2d3a52",
        },
      },
      fontFamily: {
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        mono:    ['JetBrains Mono', 'Fira Code', 'monospace'],
        display: ['Outfit', 'sans-serif'],
      },
      backgroundImage: {
        'gradient-radial':     'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic':      'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'surface-gradient':    'linear-gradient(135deg, #0e1219 0%, #141822 100%)',
        'card-gradient':       'linear-gradient(135deg, rgba(79,126,255,0.05) 0%, rgba(124,92,252,0.03) 100%)',
        'glow-primary':        'radial-gradient(circle at center, rgba(79,126,255,0.15) 0%, transparent 70%)',
        'hero-gradient':       'linear-gradient(135deg, #080b12 0%, #0f1628 50%, #080b12 100%)',
      },
      boxShadow: {
        'glow-primary':  '0 0 40px rgba(79, 126, 255, 0.15)',
        'glow-secondary':'0 0 40px rgba(124, 92, 252, 0.15)',
        'card':          '0 4px 24px rgba(0,0,0,0.4)',
        'card-hover':    '0 8px 40px rgba(0,0,0,0.6)',
        'inset-glow':    'inset 0 1px 0 rgba(255,255,255,0.05)',
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down":    { from: { height: "0" }, to:   { height: "var(--radix-accordion-content-height)" } },
        "accordion-up":      { from: { height: "var(--radix-accordion-content-height)" }, to: { height: "0" } },
        "fade-in":           { from: { opacity: "0", transform: "translateY(10px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        "slide-in-right":    { from: { transform: "translateX(100%)" }, to: { transform: "translateX(0)" } },
        "pulse-slow":        { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0.5" } },
        "shimmer":           { "0%": { backgroundPosition: "-200% 0" }, "100%": { backgroundPosition: "200% 0" } },
        "glow":              { "0%, 100%": { boxShadow: "0 0 20px rgba(79,126,255,0.2)" }, "50%": { boxShadow: "0 0 40px rgba(79,126,255,0.4)" } },
      },
      animation: {
        "accordion-down":  "accordion-down 0.2s ease-out",
        "accordion-up":    "accordion-up 0.2s ease-out",
        "fade-in":         "fade-in 0.4s ease-out",
        "slide-in-right":  "slide-in-right 0.3s ease-out",
        "pulse-slow":      "pulse-slow 3s ease-in-out infinite",
        "shimmer":         "shimmer 2s linear infinite",
        "glow":            "glow 3s ease-in-out infinite",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;

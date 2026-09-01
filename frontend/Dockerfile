# ── ClarityTI Frontend Dockerfile ─────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# Install dependencies based on lockfiles
COPY package.json package-lock.json* ./
RUN npm ci

# ── Builder stage ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy installed deps from previous stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

# Enable Next.js standalone output for a minimal production image
RUN npm run build

# ── Production runner image ────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME="0.0.0.0"

# Create a non-root user for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser  --system --uid 1001 nextjs

# Copy only what's needed to run the app
COPY --from=builder /app/package.json  ./package.json
COPY --from=builder /app/node_modules  ./node_modules
COPY --from=builder /app/.next         ./.next

# Copy public folder only if it exists (next.js optional)
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs

EXPOSE 3000

CMD ["npm", "start"]

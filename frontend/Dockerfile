# Argus 前端 Dockerfile
# 多阶段构建：deps 安装依赖，builder 构建静态资源，runner 运行 Next.js

# ---- Dependencies ----
FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json ./
RUN npm install

# ---- Builder ----
FROM node:22-alpine AS builder

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# 构建时环境变量
ENV NEXT_TELEMETRY_DISABLED=1

# 构建时设置后端内部地址（rewrites 在 build 时解析）
ARG BACKEND_INTERNAL_URL=http://backend:8000
ENV BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL}

RUN npm run build

# ---- Runner ----
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

# 创建非 root 用户运行
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# 复制构建产物
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000 \
    HOSTNAME="0.0.0.0" \
    BACKEND_INTERNAL_URL=http://backend:8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost:3000 || exit 1

CMD ["node", "server.js"]

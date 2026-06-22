import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",

  // 将 /api 请求代理到后端 FastAPI 服务
  // 使用环境变量支持 Docker 部署（容器内用服务名 backend）
  async rewrites() {
    const backendUrl = process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

import type { Metadata } from "next";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Argus - AI 漏洞挖掘平台",
  description: "Argus 是一个基于 AI 多智能体的自动化安全漏洞挖掘系统，用于发现和分析 Web 应用安全漏洞。",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN" className="dark">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

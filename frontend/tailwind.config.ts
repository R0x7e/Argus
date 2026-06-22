import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "argus-primary": "#6366f1",   // indigo — 主色调
        "argus-dark": "#0f172a",      // slate-900 — 深色背景
        "argus-card": "#1e293b",      // slate-800 — 卡片背景
        "argus-border": "#334155",    // slate-700 — 边框色
      },
    },
  },
  plugins: [],
};

export default config;

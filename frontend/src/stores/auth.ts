// ============================================================
// Argus 认证状态管理 — Zustand store
// ============================================================

import { create } from "zustand";
import { persist } from "zustand/middleware";

/** 用户信息 */
export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: string;
}

/** 认证状态 */
interface AuthState {
  token: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  login: (token: string, user: AuthUser) => void;
  logout: () => void;
  setUser: (user: AuthUser) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      isAuthenticated: false,

      login: (token, user) =>
        set({ token, user, isAuthenticated: true }),

      logout: () => {
        // 清除后端 httpOnly cookie
        if (typeof window !== "undefined") {
          fetch("/api/v1/auth/logout", {
            method: "POST",
            credentials: "include",
          }).catch(() => {});
        }
        set({ token: null, user: null, isAuthenticated: false });
      },

      setUser: (user) => set({ user }),
    }),
    {
      name: "argus-auth",
    }
  )
);

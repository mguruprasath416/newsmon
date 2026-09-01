import { create } from 'zustand';

interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

interface AuthStore {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  login: (user: User, accessToken: string, refreshToken: string) => void;
  logout: () => void;
  updateUser: (user: Partial<User>) => void;
}

export const useAuthStore = create<AuthStore>()((set) => ({
  user: {
    id: "60c72b2f9b1d8b0015b6d9a0",
    email: "analyst@newsmon.io",
    full_name: "Security Analyst",
    role: "admin",
  },
  accessToken: "dev_token",
  refreshToken: "dev_refresh_token",
  isAuthenticated: true,

  login: (user, accessToken, refreshToken) => {
    set({ user, accessToken, refreshToken, isAuthenticated: true });
  },

  logout: () => {
    set({
      user: {
        id: "60c72b2f9b1d8b0015b6d9a0",
        email: "analyst@newsmon.io",
        full_name: "Security Analyst",
        role: "admin",
      },
      isAuthenticated: true,
    });
  },

  updateUser: (partial) =>
    set((state) => ({ user: state.user ? { ...state.user, ...partial } : null })),
}));

// ── UI Store ─────────────────────────────────────────────────────────────────
interface UIStore {
  sidebarCollapsed: boolean;
  commandPaletteOpen: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (val: boolean) => void;
  openCommandPalette: () => void;
  closeCommandPalette: () => void;
}

export const useUIStore = create<UIStore>((set) => ({
  sidebarCollapsed: false,
  commandPaletteOpen: false,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setSidebarCollapsed: (val) => set({ sidebarCollapsed: val }),
  openCommandPalette: () => set({ commandPaletteOpen: true }),
  closeCommandPalette: () => set({ commandPaletteOpen: false }),
}));

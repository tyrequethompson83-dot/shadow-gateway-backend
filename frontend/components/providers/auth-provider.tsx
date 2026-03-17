"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { ApiError, getMe, login as apiLogin, logout as apiLogout } from "@/lib/api";
import { clearToken, readToken, writeToken } from "@/lib/auth-storage";
import type { AuthResponse, MeResponse } from "@/types/api";

type LoginInput = {
  email: string;
  password: string;
  tenantId?: number;
};

type AuthContextValue = {
  token: string;
  user: MeResponse | null;
  isBooting: boolean;
  isAuthenticated: boolean;
  completeAuth: (auth: AuthResponse) => Promise<void>;
  login: (input: LoginInput) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

function normalizeApiError(err: unknown): Error {
  if (err instanceof Error) {
    return err;
  }
  return new Error("Unexpected auth error");
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState("");
  const [user, setUser] = useState<MeResponse | null>(null);
  const [isBooting, setIsBooting] = useState(true);

  const clearSession = useCallback(() => {
    clearToken();
    setToken("");
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const currentToken = token || readToken();
    if (!currentToken) {
      clearSession();
      return;
    }

    try {
      const me = await getMe(currentToken);
      writeToken(currentToken);
      setToken(currentToken);
      setUser(me);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        clearSession();
        return;
      }
      throw normalizeApiError(err);
    }
  }, [token, clearSession]);

  const completeAuth = useCallback(async (auth: AuthResponse) => {
    const accessToken = String(auth.access_token || "");
    if (!accessToken) {
      throw new Error("Authentication token missing from response");
    }

    writeToken(accessToken);
    setToken(accessToken);
    const me = await getMe(accessToken);
    setUser(me);
  }, []);

  useEffect(() => {
    let active = true;
    const init = async () => {
      const savedToken = readToken();
      if (!savedToken) {
        if (active) {
          setIsBooting(false);
        }
        return;
      }

      try {
        const me = await getMe(savedToken);
        if (!active) {
          return;
        }
        setToken(savedToken);
        setUser(me);
      } catch {
        if (!active) {
          return;
        }
        clearSession();
      } finally {
        if (active) {
          setIsBooting(false);
        }
      }
    };

    init();
    return () => {
      active = false;
    };
  }, [clearSession]);

  const login = useCallback(async (input: LoginInput) => {
    const payload: { email: string; password: string; tenant_id?: number } = {
      email: input.email,
      password: input.password,
    };
    if (input.tenantId && Number.isFinite(input.tenantId)) {
      payload.tenant_id = input.tenantId;
    }

    const auth = await apiLogin(payload);
    await completeAuth(auth);
  }, [completeAuth]);

  const logout = useCallback(async () => {
    const currentToken = token || readToken();
    if (currentToken) {
      try {
        await apiLogout(currentToken);
      } catch {
        // no-op; local session should still be cleared
      }
    }
    clearSession();
  }, [token, clearSession]);

  const value = useMemo<AuthContextValue>(
    () => ({
      token,
      user,
      isBooting,
      isAuthenticated: Boolean(token && user),
      completeAuth,
      login,
      logout,
      refreshUser,
    }),
    [token, user, isBooting, completeAuth, login, logout, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuthContext must be used inside AuthProvider");
  }
  return value;
}


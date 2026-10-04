import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, getToken, setToken, type User } from './api'

type AuthState = {
  user: User | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<User>
  signUp: (email: string, password: string) => Promise<{ user: User; devVerifyUrl?: string }>
  signOut: () => void
  refresh: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(!!getToken())

  const refresh = useCallback(async () => {
    if (!getToken()) return setUser(null)
    try {
      setUser((await api.me()).user)
    } catch {
      setToken(null)
      setUser(null)
    }
  }, [])

  useEffect(() => {
    refresh().finally(() => setLoading(false))
  }, [refresh])

  const value: AuthState = {
    user,
    loading,
    refresh,
    signIn: async (email, password) => {
      const r = await api.signIn(email, password)
      setToken(r.token)
      setUser(r.user)
      return r.user
    },
    signUp: async (email, password) => {
      const r = await api.signUp(email, password)
      setToken(r.token)
      setUser(r.user)
      return r
    },
    signOut: () => {
      setToken(null)
      setUser(null)
    },
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}

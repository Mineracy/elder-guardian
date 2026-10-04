import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../auth'

export default function Login() {
  const [params] = useSearchParams()
  const [mode, setMode] = useState<'signin' | 'signup'>(params.get('mode') === 'signup' ? 'signup' : 'signin')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { user, signIn, signUp } = useAuth()
  const navigate = useNavigate()

  if (user) return <Navigate to="/dashboard" replace />

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const f = new FormData(e.currentTarget)
    const email = String(f.get('email'))
    const password = String(f.get('password'))
    setBusy(true)
    setError('')
    try {
      mode === 'signin' ? await signIn(email, password) : await signUp(email, password)
      navigate('/dashboard')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="narrow">
      <form className="card form" onSubmit={submit}>
        <h1>{mode === 'signin' ? 'Elder Guardian sign in' : 'Create an Elder Guardian account'}</h1>
        {mode === 'signup' && (
          <p className="muted">
            Use the email address the person you’re protecting entered for you. We’ll send a link to confirm it’s yours.
          </p>
        )}
        {error && <p className="alert error" role="alert">{error}</p>}
        <label>Email<input type="email" name="email" required autoComplete="username" /></label>
        <label>
          Password
          <input type="password" name="password" required minLength={8}
            autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} />
        </label>
        <button className="btn primary big" disabled={busy}>
          {busy ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account'}
        </button>
        <button type="button" className="link" onClick={() => setMode(mode === 'signin' ? 'signup' : 'signin')}>
          {mode === 'signin' ? 'New Elder Guardian? Create an account' : 'Already have an account? Sign in'}
        </button>
      </form>
    </main>
  )
}

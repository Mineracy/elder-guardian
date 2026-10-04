import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, ApiError, type Protectee } from '../api'
import { useAuth } from '../auth'
import ProtecteeCard from '../components/ProtecteeCard'

const REFRESH_MS = 10_000

export default function Dashboard() {
  const { user, refresh } = useAuth()
  const [params] = useSearchParams()
  const [protectees, setProtectees] = useState<Protectee[] | null>(null)
  const [needsVerify, setNeedsVerify] = useState(!user?.email_verified)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setProtectees((await api.dashboard()).protectees)
      setNeedsVerify(false)
      setError('')
    } catch (e) {
      if (e instanceof ApiError && e.message === 'verify_email') setNeedsVerify(true)
      else setError(e instanceof Error ? e.message : 'Could not load your dashboard')
    }
  }, [])

  useEffect(() => {
    if (params.get('verified')) refresh().then(load)
  }, [params, refresh, load])

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_MS) // new requests show up without a manual reload
    return () => clearInterval(t)
  }, [load])

  async function resend() {
    try {
      const r = await api.resendVerification()
      setNotice(
        r.devVerifyUrl
          ? `Dev mode: open ${r.devVerifyUrl}`
          : `We sent a new confirmation link to ${user?.email}.`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not send the email')
    }
  }

  if (needsVerify) {
    return (
      <main className="narrow">
        <div className="card">
          <h1>Confirm your email</h1>
          <p>
            Check <strong>{user?.email}</strong> for a confirmation link. We do this so only you can approve
            requests for the people you protect.
          </p>
          {notice && <p className="alert">{notice}</p>}
          {error && <p className="alert error">{error}</p>}
          <div className="row">
            <button className="btn primary" onClick={resend}>Resend email</button>
            <button className="btn ghost" onClick={load}>I’ve confirmed it</button>
          </div>
        </div>
      </main>
    )
  }

  return (
    <main className="wide">
      <h1>Your dashboard</h1>
      {params.get('verified') && <p className="alert">Thanks, your email is confirmed.</p>}
      {error && <p className="alert error" role="alert">{error}</p>}
      {protectees === null ? (
        <p className="muted">Loading…</p>
      ) : protectees.length === 0 ? (
        <div className="card">
          <h2>No one to look after yet</h2>
          <p className="muted">
            When someone adds <strong>{user?.email}</strong> as their trusted contact in the Elder Guardian extension,
            they’ll appear here.
          </p>
        </div>
      ) : (
        <div className="stack">
          {protectees.map((p) => (
            <ProtecteeCard key={p.id} person={p} onChanged={load} />
          ))}
        </div>
      )}
    </main>
  )
}

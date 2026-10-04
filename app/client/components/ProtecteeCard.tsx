import { useState } from 'react'
import { api, type Activity, type Protectee } from '../api'

const TRIGGER_LABELS: Record<string, string> = {
  NON_WHITELISTED_DOMAIN: 'Site not on trusted list',
  FAKE_TECH_SUPPORT_POPUP: 'Fake tech-support page',
  DANGEROUS_REMOTE_TOOL_DOWNLOAD: 'Remote-access tool download',
}

function ActivityRow({ item, onChanged }: { item: Activity; onChanged: () => void }) {
  const [addToWhitelist, setAdd] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function decide(decision: 'allow' | 'deny') {
    setBusy(true)
    setError('')
    try {
      await api.decide(item.id, decision, decision === 'allow' && addToWhitelist)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save your decision')
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className={`activity ${item.status}`}>
      <div className="activity-head">
        <span className={`badge ${item.threat_level}`}>{item.threat_level}</span>
        <span className="muted small">
          {TRIGGER_LABELS[item.trigger_type] ?? item.trigger_type} · {new Date(item.created_at).toLocaleString()}
        </span>
        {item.status !== 'pending' && <span className={`status ${item.status}`}>{item.status}</span>}
      </div>
      <code className="url">{item.target_url}</code>
      <p className="summary">{item.risk_summary}</p>
      {item.status === 'pending' && (
        <>
          <div className="row">
            <button className="btn allow" disabled={busy} onClick={() => decide('allow')}>Allow</button>
            <button className="btn deny" disabled={busy} onClick={() => decide('deny')}>Deny</button>
          </div>
          <label className="check">
            <input type="checkbox" checked={addToWhitelist} onChange={(e) => setAdd(e.target.checked)} />
            Add <strong>{item.domain}</strong> to their whitelist if I allow
          </label>
        </>
      )}
      {error && <p className="alert error">{error}</p>}
    </li>
  )
}

export default function ProtecteeCard({ person, onChanged }: { person: Protectee; onChanged: () => void }) {
  const [showWhitelist, setShowWhitelist] = useState(false)
  const [error, setError] = useState('')

  async function removeSelf() {
    if (!window.confirm(`Stop being ${person.email}'s trusted Elder Guardian? They'll no longer be able to get approvals from you.`)) return
    try {
      await api.removeSelf(person.id)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not remove you as an Elder Guardian')
    }
  }

  return (
    <section className="card person">
      <header className="person-head">
        <h2>
          {person.pendingCount > 0 && <span className="warn" title="Needs your attention" aria-label="Needs your attention">⚠️ </span>}
          {person.email}
        </h2>
        {person.pendingCount > 0 && <span className="pill">{person.pendingCount} waiting</span>}
      </header>

      <h3>Suspicious activity</h3>
      {person.activity.length === 0 ? (
        <p className="muted">Nothing suspicious so far. 🎉</p>
      ) : (
        <ul className="activity-list">
          {person.activity.map((a) => (
            <ActivityRow key={a.id} item={a} onChanged={onChanged} />
          ))}
        </ul>
      )}

      <div className="person-actions">
        <button className="btn ghost" aria-expanded={showWhitelist} onClick={() => setShowWhitelist((s) => !s)}>
          {showWhitelist ? 'Hide whitelist' : 'View whitelist'}
        </button>
        <button className="btn danger-ghost" onClick={removeSelf}>🗑 Remove self as trusted Elder Guardian</button>
      </div>
      {error && <p className="alert error">{error}</p>}

      {showWhitelist && (
        <div className="whitelist">
          <h3>Allowed sites ({person.whitelist.length})</h3>
          <ul>
            {person.whitelist.map((d) => <li key={d}>{d}</li>)}
          </ul>
        </div>
      )}
    </section>
  )
}

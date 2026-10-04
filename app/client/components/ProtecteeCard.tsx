import { useEffect, useState, type FormEvent } from 'react'
import { api, type Activity, type Protectee, type TransactionLimit } from '../api'

const TRIGGER_LABELS: Record<string, string> = {
  NON_WHITELISTED_DOMAIN: 'Site not on trusted list',
  FAKE_TECH_SUPPORT_POPUP: 'Fake tech-support page',
  DANGEROUS_REMOTE_TOOL_DOWNLOAD: 'Remote-access tool download',
  SUSPICIOUS_DOWNLOAD: 'Risky program download',
  GIFT_CARD_PAYMENT: 'Gift card / crypto payment request',
  GOV_IMPERSONATION_THREAT: 'Fake government or police threat',
  ACCOUNT_VERIFICATION_PHISH: 'Fake account-verification page',
  PRIZE_OR_LOTTERY: 'Fake prize or lottery',
  INSECURE_LOGIN_FORM: 'Password asked for on an unencrypted page',
  LARGE_PAYMENT_FORM: 'Large payment',
  LARGE_TRANSACTION: 'Transaction over your limit',
}

const plain = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(2))
const money = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' })

function TransactionLimitEditor({ person, onChanged }: { person: Protectee; onChanged: () => void | Promise<void> }) {
  const current = person.transactionLimit
  const [amount, setAmount] = useState(current ? plain(current.amount) : '')
  const [action, setAction] = useState<TransactionLimit['action']>(current?.action ?? 'approve')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState('')

  // Follow changes made elsewhere (another guardian, another tab) without clobbering typing on every refresh.
  useEffect(() => {
    setAmount(current ? plain(current.amount) : '')
    setAction(current?.action ?? 'approve')
  }, [current?.amount, current?.action])

  async function save(limit: TransactionLimit | null) {
    setBusy(true)
    setError('')
    setSaved('')
    try {
      await api.setTransactionLimit(person.id, limit)
      await onChanged() // refresh first so the description below already reflects the new limit
      setSaved(limit ? 'Limit saved.' : 'Limit removed.')
      if (!limit) setAmount('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the limit')
    } finally {
      setBusy(false)
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    const value = Number(amount.replace(/[$,\s]/g, ''))
    if (!Number.isFinite(value) || value <= 0) return setError('Enter an amount greater than $0')
    void save({ amount: value, action })
  }

  return (
    <div className="limit">
      <h3>Transaction limit</h3>
      <p className="muted small">
        {current
          ? `Payments or transfers over ${money(current.amount)} will ${current.action === 'approve' ? 'wait for your approval' : 'show them a warning'}.`
          : 'No limit set. Choose an amount above which a payment or transfer gets a warning or needs your approval.'}
      </p>
      <form className="limit-form" onSubmit={submit}>
        <label>
          Limit ($)
          <input type="text" inputMode="decimal" placeholder="500" value={amount} onChange={(e) => setAmount(e.target.value)} />
        </label>
        <label>
          Above the limit
          <select value={action} onChange={(e) => setAction(e.target.value as TransactionLimit['action'])}>
            <option value="approve">Require my approval</option>
            <option value="warn">Show them a warning only</option>
          </select>
        </label>
        <div className="row">
          <button className="btn primary" disabled={busy || !amount.trim()}>Save limit</button>
          {current && <button type="button" className="btn ghost" disabled={busy} onClick={() => save(null)}>Remove limit</button>}
        </div>
      </form>
      {saved && <p className="alert" role="status">{saved}</p>}
      {error && <p className="alert error" role="alert">{error}</p>}
    </div>
  )
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
      {item.amount !== null && <p className="amount">Amount: <strong>{money(item.amount)}</strong></p>}
      <code className="url">{item.target_url}</code>
      <p className="summary">{item.risk_summary}</p>
      {item.signals.length > 0 && (
        <ul className="signals" aria-label="Red flags">
          {item.signals.map((sig) => (
            <li key={sig.code} className={`signal ${sig.severity}`}>{sig.label}</li>
          ))}
        </ul>
      )}
      {item.ai_fallback && (
        <p className="muted small">AI analysis was unavailable, so this is a standard summary. Please check the link yourself.</p>
      )}
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

export default function ProtecteeCard({ person, onChanged }: { person: Protectee; onChanged: () => void | Promise<void> }) {
  const [showWhitelist, setShowWhitelist] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function editWhitelist(action: () => Promise<unknown>): Promise<boolean> {
    setBusy(true)
    setError('')
    try {
      await action()
      onChanged()
      return true
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not update the whitelist')
      return false
    } finally {
      setBusy(false)
    }
  }

  async function addDomain(e: FormEvent) {
    e.preventDefault()
    if (!newDomain.trim()) return
    if (await editWhitelist(() => api.addWhitelist(person.id, newDomain))) setNewDomain('')
  }

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

      <TransactionLimitEditor person={person} onChanged={onChanged} />

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
          <form className="row add-domain" onSubmit={addDomain}>
            <input
              type="text"
              aria-label="Domain to add"
              placeholder="example.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
            />
            <button className="btn primary" disabled={busy || !newDomain.trim()}>Add</button>
          </form>
          {person.whitelist.length === 0 ? (
            <p className="muted">Nothing is on the list yet, so every site will need your approval.</p>
          ) : (
            <ul className="whitelist-items">
              {person.whitelist.map((d) => (
                <li key={d}>
                  <span>{d}</span>
                  <button
                    className="btn danger-ghost small-btn"
                    disabled={busy}
                    aria-label={`Remove ${d} from the whitelist`}
                    onClick={() => editWhitelist(() => api.removeWhitelist(person.id, d))}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  )
}

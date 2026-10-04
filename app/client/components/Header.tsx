import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'

export default function Header() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  return (
    <header className="site-header">
      <Link to="/" className="brand">🛡️ Elder Guardian</Link>
      <nav>
        {user ? (
          <>
            <Link to="/dashboard">Dashboard</Link>
            <button className="btn ghost" onClick={() => { signOut(); navigate('/') }}>Sign out</button>
          </>
        ) : (
          <Link to="/login" className="btn primary">Elder Guardian login</Link>
        )}
      </nav>
    </header>
  )
}

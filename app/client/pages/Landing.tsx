import { Link } from 'react-router-dom'

const steps = [
  ['1', 'They browse as usual', 'The Elder Guardian extension quietly watches for sites that aren’t on their approved list, fake “your computer is locked” pages and remote-access downloads.'],
  ['2', 'Risky pages are paused', 'Instead of loading, the page waits on a calm “Awaiting verification” screen while an AI safety agent explains the risk.'],
  ['3', 'You decide', 'You get an email with the details and a clear Allow or Deny. Approve a site once, or add it to their trusted list for good.'],
  ['4', 'They learn for next time', 'If you deny, they see a warm, plain-language explanation of the warning signs, never a lecture.'],
]

export default function Landing() {
  return (
    <main>
      <section className="hero">
        <h1>Be the safety net for the people you love.</h1>
        <p className="lead">
          Scams target parents, grandparents and anyone who’s new to the internet. Elder Guardian pauses risky links and
          asks someone they trust before anything bad can happen.
        </p>
        <div className="cta">
          <Link to="/login?mode=signup" className="btn primary big">Become an Elder Guardian</Link>
          <a href="#how" className="btn ghost big">How it works</a>
        </div>
      </section>

      <section id="how" className="section">
        <h2>How it works</h2>
        <ol className="steps">
          {steps.map(([n, title, body]) => (
            <li key={n} className="card">
              <span className="step-n">{n}</span>
              <h3>{title}</h3>
              <p>{body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="section">
        <h2>Built to be respectful</h2>
        <div className="grid3">
          <div className="card"><h3>Only you can approve</h3><p>Sites join the approved list only when their Elder Guardian says so, so a scammer on the phone can’t talk them into bypassing it.</p></div>
          <div className="card"><h3>Never condescending</h3><p>Explanations are written to teach, not to blame, with the specific signs to watch for next time.</p></div>
          <div className="card"><h3>You stay in control</h3><p>Review every event in your dashboard, see their trusted sites, and step down as an Elder Guardian whenever you like.</p></div>
        </div>
      </section>

      <footer className="footer">
        <p>Elder Guardian · Helping everyone stay safe online</p>
      </footer>
    </main>
  )
}

/**
 * Records a trusted contact's decision. The `status = 'pending'` guard makes the first answer win,
 * and an expired request can never be allowed. Returns the final status.
 */
export async function resolveIntervention(
  db: D1Database,
  req: { id: string; user_id: string; domain: string; expires_at: number },
  decision: 'allowed' | 'denied',
  addToWhitelist: boolean,
): Promise<string> {
  if (req.expires_at < Date.now()) decision = 'denied'

  const res = await db
    .prepare("UPDATE intervention_requests SET status = ?, resolved_at = ? WHERE id = ? AND status = 'pending'")
    .bind(decision, Date.now(), req.id)
    .run()

  if (res.meta.changes === 0) {
    const row = await db
      .prepare('SELECT status FROM intervention_requests WHERE id = ?')
      .bind(req.id)
      .first<{ status: string }>()
    return row?.status ?? 'denied'
  }

  if (decision === 'allowed' && addToWhitelist) {
    await db
      .prepare('INSERT OR IGNORE INTO whitelist_domains (id, user_id, domain, created_at) VALUES (?, ?, ?, ?)')
      .bind(crypto.randomUUID(), req.user_id, req.domain, Date.now())
      .run()
  }
  return decision
}

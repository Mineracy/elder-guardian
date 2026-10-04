-- Heuristic scam signals found for a request (JSON array of {code,label,severity}) and, when the
-- AI analysis fell back to the canned response, why (kept server-side to diagnose Gemini failures).
ALTER TABLE intervention_requests ADD COLUMN signals TEXT;
ALTER TABLE intervention_requests ADD COLUMN ai_error TEXT;

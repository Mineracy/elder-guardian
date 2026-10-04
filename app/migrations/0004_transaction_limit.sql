-- Per-person transaction limit set by their guardian (NULL = no limit), and what happens above it:
-- 'approve' holds the transaction until a guardian approves, 'warn' only shows a warning.
ALTER TABLE users ADD COLUMN transaction_limit_cents INTEGER;
ALTER TABLE users ADD COLUMN transaction_limit_action TEXT NOT NULL DEFAULT 'approve';

-- The amount (in cents) of the transaction that triggered an intervention, if any.
ALTER TABLE intervention_requests ADD COLUMN amount_cents INTEGER;

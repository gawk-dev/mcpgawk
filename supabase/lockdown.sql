-- FINAL LOCKDOWN — run this ONLY after /api/lead is deployed and verified working.
-- It removes the public (anon/publishable-key) insert policy, so after this the ONLY
-- way a row can enter `leads` is through the serverless function using the service-role
-- key. Direct POSTs to the REST API with the publishable key will start returning 401/403.
--
-- Verify first:  submit the live form once and confirm the row lands.
-- Then run this. To reverse (re-open public insert) see leads.sql.

drop policy if exists "anon can insert a lead" on public.leads;

-- (RLS stays enabled; with no INSERT policy for anon/authenticated, only the
--  service-role key — which bypasses RLS — can write. That key lives only in Vercel.)

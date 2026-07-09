-- mcpgawk lead capture — run once in the Supabase SQL editor.
-- Design: the anon key is public by design. Safety comes from RLS:
--   anon may INSERT a lead, and NOTHING may SELECT. So the endpoint can
--   collect signups but the list can never be read back through the API.
-- Read the leads from the Supabase dashboard (service role), not the client.

create table if not exists public.leads (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  name        text        not null check (char_length(name)  between 1 and 120),
  email       text        not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' and char_length(email) <= 200),
  company     text        check (char_length(company) <= 160),
  wants_scan  boolean     not null default false,  -- "scan my own server" waitlist
  opt_in      boolean     not null default false,  -- marketing consent (must be explicit)
  source      text        not null default 'mcp.gawk.dev' check (char_length(source) <= 80)
);

-- One row per email is enough signal; ignore duplicate re-submits gracefully.
create unique index if not exists leads_email_key on public.leads (lower(email));

alter table public.leads enable row level security;

-- INSERT-only for the anonymous web client. No SELECT/UPDATE/DELETE policy
-- exists, so RLS denies all of those to anon/authenticated by default.
drop policy if exists "anon can insert a lead" on public.leads;
create policy "anon can insert a lead"
  on public.leads for insert
  to anon
  with check (true);

-- NOTE (anti-spam): a naked public insert endpoint gets bots. The client adds
-- a honeypot + min-fill-time. For a trustworthy signal at volume, front this
-- with Cloudflare Turnstile (needs an edge function to verify the token) — the
-- table + policy above are unchanged when you add it.

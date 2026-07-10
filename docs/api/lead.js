// Vercel serverless function — the ONLY path into the `leads` table.
// Verifies Cloudflare Turnstile server-side, runs honeypot/timing/email guards,
// then inserts using the Supabase service-role key (never exposed to the browser).
// Env vars (set in Vercel → Settings → Environment Variables):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE, TURNSTILE_SECRET
const DISPOSABLE = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com','temp-mail.org',
  'trashmail.com','yopmail.com','getnada.com','sharklasers.com','maildrop.cc','dispostable.com',
  'mailnesia.com','fakeinbox.com','throwawaymail.com','mohmal.com','mintemail.com'
]);

export default async function handler(req, res) {
  if (req.method !== 'POST') { res.status(405).json({ error: 'method' }); return; }

  const SITE = process.env.SUPABASE_URL;
  const KEY  = process.env.SUPABASE_SERVICE_ROLE;
  const TS   = process.env.TURNSTILE_SECRET;
  if (!SITE || !KEY || !TS) { res.status(500).json({ error: 'not-configured' }); return; }

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (_) { body = {}; } }
  body = body || {};

  // 1) honeypot — a bot filled the hidden field. Pretend success, insert nothing.
  if (body.website) { res.status(200).json({ ok: true }); return; }

  // 2) timing — the form must have been open at least a couple of seconds (and not for days).
  const elapsed = Number(body.elapsed || 0);
  if (!(elapsed >= 2500 && elapsed < 1000 * 60 * 60 * 6)) { res.status(400).json({ error: 'timing' }); return; }

  // 3) field validation
  const name  = String(body.name || '').trim().slice(0, 120);
  const email = String(body.email || '').trim().slice(0, 200).toLowerCase();
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { res.status(400).json({ error: 'fields' }); return; }
  if (DISPOSABLE.has(email.split('@')[1])) { res.status(400).json({ error: 'disposable' }); return; }

  // 4) Turnstile — verify the token with Cloudflare (this is what a bot cannot fake).
  const token = String(body.turnstileToken || '');
  if (!token) { res.status(400).json({ error: 'captcha-missing' }); return; }
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  let verify;
  try {
    verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: TS, response: token, remoteip: ip })
    }).then(r => r.json());
  } catch (_) { verify = { success: false }; }
  if (!verify || !verify.success) { res.status(400).json({ error: 'captcha-failed' }); return; }

  // 5) insert via service-role (bypasses RLS; the public key can no longer write once the policy is dropped).
  const ins = await fetch(SITE.replace(/\/$/, '') + '/rest/v1/leads', {
    method: 'POST',
    headers: {
      apikey: KEY, Authorization: 'Bearer ' + KEY,
      'Content-Type': 'application/json', Prefer: 'return=minimal'
    },
    body: JSON.stringify({
      name, email,
      company: String(body.company || '').trim().slice(0, 160) || null,
      wants_scan: !!body.wants_scan,
      opt_in: !!body.opt_in,
      source: 'mcp.gawk.dev'
    })
  });
  if (ins.status === 201 || ins.status === 409) { res.status(200).json({ ok: true }); return; }  // created, or already on the list
  const detail = await ins.text().catch(() => '');
  res.status(502).json({ error: 'insert', detail: detail.slice(0, 200) });
}

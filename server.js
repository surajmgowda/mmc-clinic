// MMC Clinic — server.js
// A small Express server that serves the clinic web app and persists
// all clinic data (patients, visits, staff, clinic info) as a single
// JSON document in Postgres, so every device sees the same records.

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable. Set it to your Postgres connection string.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Most hosted Postgres providers (Render, Neon, Supabase) require SSL.
  // Set DB_SSL=false in your environment for local development against a
  // Postgres server that does not support SSL.
  ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
});

// ---- Real server-side sessions ----
// The staff PIN is now verified here, not in the browser. A successful
// /api/login issues a signed, HttpOnly session cookie; /api/data requires
// a valid one. No cookie, no data — "staff name in the browser" is no
// longer treated as proof of anything.
//
// Sessions are stateless signed tokens (HMAC-SHA256), not a server-side
// session table — simplest thing that actually works without a new DB
// migration or dependency. The real tradeoff: logout can't force-revoke a
// token that's already out in the wild before it expires (12h). If you
// need hard revocation (e.g. a compromised device), shortening
// SESSION_MAX_AGE_MS or adding a server-side revocation list is the next
// increment — flagging it rather than pretending it's solved here.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. Using a random secret generated for this run — ' +
    'every session will be invalidated on the next restart/redeploy. Set SESSION_SECRET in your ' +
    'environment (a long random string) for stable sessions across restarts.');
}
const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000; // 12 hours

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}
function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIE === 'true';
  res.setHeader('Set-Cookie',
    `mmc_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_MAX_AGE_MS / 1000)}; SameSite=Lax${secure ? '; Secure' : ''}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'mmc_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}
function requireSession(req, res, next) {
  const payload = verifySession(parseCookies(req).mmc_session);
  if (!payload) return res.status(401).json({ error: 'not logged in' });
  req.staffSession = payload;
  next();
}

// ---- Salted password hashing (scrypt), with transparent migration off the
// old client-computed, unsalted SHA-256 hashes the first time each staff
// member logs in through this endpoint. ----
function hashPinSalted(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function verifyPinSalted(pin, stored) {
  if (typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false;
  const parts = stored.split('$');
  if (parts.length !== 3) return false;
  const [, salt, hash] = parts;
  const check = crypto.scryptSync(pin, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function looksLegacyHash(stored) {
  return typeof stored === 'string' && stored.length === 64 && /^[0-9a-f]+$/.test(stored);
}
function verifyPinLegacy(pin, stored) {
  const hash = crypto.createHash('sha256').update(pin).digest('hex');
  const a = Buffer.from(hash);
  const b = Buffer.from(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---- Server-side login rate limiting ----
// Same escalating-cooldown idea as the (still-present) client-side one, but
// this one can't be cleared by wiping localStorage — it's the real gate now.
// In-memory, so it resets on a server restart; acceptable for opportunistic
// guessing, not a defense against a determined attacker with restart access.
const loginAttempts = new Map(); // staffName -> {fails, lockCount, lockedUntil}
const LOCK_THRESHOLD = 5, LOCK_BASE_MS = 30 * 1000, LOCK_MAX_MS = 15 * 60 * 1000;
function msLockedFor(name) {
  const rec = loginAttempts.get(name);
  if (rec && rec.lockedUntil && Date.now() < rec.lockedUntil) return rec.lockedUntil - Date.now();
  return 0;
}
function recordFailedLogin(name) {
  const rec = loginAttempts.get(name) || { fails: 0, lockCount: 0 };
  rec.fails++;
  if (rec.fails >= LOCK_THRESHOLD) {
    rec.lockCount++;
    rec.lockedUntil = Date.now() + Math.min(LOCK_BASE_MS * Math.pow(2, rec.lockCount - 1), LOCK_MAX_MS);
    rec.fails = 0;
  }
  loginAttempts.set(name, rec);
}
function clearFailedLogins(name) {
  loginAttempts.delete(name);
}

function defaultData() {
  return {
    clinicInfo: { name: 'Male Madeshwara Clinic', shortName: 'MMC', address: '', phone: '' },
    nextPatientSeq: 1,
    patients: [],
    staff: []
  };
}

async function ensureStore() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clinic_store (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  const { rows } = await pool.query('SELECT id FROM clinic_store WHERE id = 1');
  if (rows.length === 0) {
    await pool.query(
      'INSERT INTO clinic_store (id, data, version) VALUES (1, $1, 1)',
      [defaultData()]
    );
    console.log('Initialized clinic_store with default data.');
  }
}

// ---- Optional site-wide password gate ----
// Set SITE_USER and SITE_PASS to require a browser login (HTTP Basic Auth)
// before anyone can even load the page. Strongly recommended, since this
// app handles patient health information. If left unset, the app runs
// without this extra gate (only the in-app staff PIN screen applies).
function basicAuthMiddleware(req, res, next) {
  const user = process.env.SITE_USER;
  const pass = process.env.SITE_PASS;
  if (!user || !pass) return next();

  const header = req.headers.authorization;
  if (header && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    const u = decoded.slice(0, sep);
    const p = decoded.slice(sep + 1);
    if (u === user && p === pass) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="MMC Clinic"');
  res.status(401).send('Authentication required.');
}

app.use(basicAuthMiddleware);
app.use(express.json({ limit: '5mb' }));

// ---- Auth API ----
// The PIN now gets checked here, server-side, against the real stored hash
// — not in the browser against a copy of the data the browser was handed.
app.post('/api/login', async (req, res) => {
  const { staffName, pin } = req.body || {};
  if (!staffName || !pin) return res.status(400).json({ error: 'staffName and pin are required' });

  const remainingMs = msLockedFor(staffName);
  if (remainingMs > 0) {
    return res.status(429).json({ error: 'locked', remainingMs });
  }

  try {
    const { rows } = await pool.query('SELECT data, version FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    const staff = (clinicData.staff || []).find(s => s.name === staffName);
    if (!staff) {
      recordFailedLogin(staffName);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    let ok = false;
    if (looksLegacyHash(staff.pin)) {
      ok = verifyPinLegacy(pin, staff.pin);
      if (ok) {
        // First real server-side verification for this account — upgrade
        // the stored hash to a salted one now that we've confirmed the PIN.
        staff.pin = hashPinSalted(pin);
        await pool.query(
          'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
          [clinicData]
        );
      }
    } else {
      ok = verifyPinSalted(pin, staff.pin);
    }

    if (!ok) {
      recordFailedLogin(staffName);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    clearFailedLogins(staffName);
    const token = signSession({
      name: staff.name, role: staff.role, owner: !!staff.owner, exp: Date.now() + SESSION_MAX_AGE_MS
    });
    setSessionCookie(res, token);
    res.json({ ok: true, name: staff.name, role: staff.role, owner: !!staff.owner });
  } catch (e) {
    console.error('POST /api/login failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

// Lets the frontend check "am I still logged in?" (e.g. after a page
// reload) without needing to also fetch the full clinic data first.
app.get('/api/session', (req, res) => {
  const payload = verifySession(parseCookies(req).mmc_session);
  if (!payload) return res.status(401).json({ error: 'not logged in' });
  res.json({ ok: true, name: payload.name, role: payload.role, owner: payload.owner });
});

// Just enough for the login screen to render (names + roles) without
// requiring a session first — no PINs, no patient data, nothing sensitive.
// Still sits behind basicAuthMiddleware (the site-wide gate), same as
// everything else.
app.get('/api/staff-list', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const staff = (rows[0].data.staff || []).map(s => ({ name: s.name, role: s.role }));
    res.json({ staff, setupNeeded: staff.length === 0 });
  } catch (e) {
    console.error('GET /api/staff-list failed:', e);
    res.status(500).json({ error: 'database error' });
  }
});

// First-time bootstrap only. Deliberately self-limiting: checks the real,
// current server-side staff count, not anything the client claims — so
// this can never be used to add a second account. That's what closed the
// addStaffFromLogin() hole; this must not reopen an equivalent one.
app.post('/api/setup', async (req, res) => {
  const { name, role, pin } = req.body || {};
  if (!name || !role || !pin) return res.status(400).json({ error: 'name, role and pin are required' });
  try {
    const { rows } = await pool.query('SELECT data, version FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    if ((clinicData.staff || []).length > 0) {
      return res.status(403).json({ error: 'setup already completed — ask an existing admin to add your account' });
    }
    const staffRecord = { name, role, pin: hashPinSalted(pin), owner: true, qualification: '' };
    clinicData.staff = [staffRecord];
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    const token = signSession({ name, role, owner: true, exp: Date.now() + SESSION_MAX_AGE_MS });
    setSessionCookie(res, token);
    res.json({ ok: true, name, role, owner: true });
  } catch (e) {
    console.error('POST /api/setup failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Data API ----
// Both routes now require a valid session — the PIN screen is no longer
// just a UI gate in front of data anyone could already reach directly.
app.get('/api/data', requireSession, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data, version FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    res.json({ data: rows[0].data, version: rows[0].version });
  } catch (e) {
    console.error('GET /api/data failed:', e);
    res.status(500).json({ error: 'database error' });
  }
});

// Whole-document save with optimistic concurrency: the client sends the
// version it last read. If another device saved in the meantime, this
// returns 409 with the newer copy instead of silently overwriting it.
app.put('/api/data', requireSession, async (req, res) => {
  const { version, data } = req.body || {};
  if (typeof version !== 'number' || !data || typeof data !== 'object') {
    return res.status(400).json({ error: 'version (number) and data (object) are required' });
  }
  try {
    const { rows } = await pool.query('SELECT version, data FROM clinic_store WHERE id = 1');
    const current = rows[0];
    if (current.version !== version) {
      return res.status(409).json({ data: current.data, version: current.version });
    }
    const newVersion = current.version + 1;
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = $2, updated_at = now() WHERE id = 1',
      [data, newVersion]
    );
    res.json({ ok: true, version: newVersion });
  } catch (e) {
    console.error('PUT /api/data failed:', e);
    res.status(500).json({ error: 'database error' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---- PWA files ----
// Served explicitly, with the right Content-Type, before the catch-all below
// — otherwise the SPA fallback would hand back index.html for these paths
// instead of the actual manifest/service worker, breaking installability.
app.get('/manifest.json', (req, res) => {
  res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, 'manifest.json'));
});
app.get('/service-worker.js', (req, res) => {
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// ---- Frontend ----
// Single self-contained HTML file (all CSS/JS inline) — served for every
// other non-API route.
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

ensureStore()
  .then(() => {
    app.listen(PORT, () => console.log(`MMC clinic server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to initialize the database:', err);
    process.exit(1);
  });

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
// Render (and most PaaS hosts) terminate TLS at a proxy in front of the app
// and forward requests over plain HTTP internally — without this, Express
// has no way to know the original request was HTTPS, and req.secure would
// always read false even on your HTTPS-only production site.
app.set('trust proxy', 1);

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
function setSessionCookie(req, res, token) {
  // req.secure is the real signal now that 'trust proxy' is set — true
  // whenever the original request came in over HTTPS, which on Render it
  // always will. The env vars remain as an explicit override for hosting
  // setups where that detection isn't reliable.
  const secure = req.secure || process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIE === 'true';
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

// ---- Salted secret hashing (scrypt), with transparent migration off the
// old client-computed, unsalted SHA-256 hashes the first time each staff
// member authenticates through this endpoint. Used for PIN, password, and
// recovery codes. ----
function hashSecretSalted(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function hashPinSalted(pin) { return hashSecretSalted(pin); }
function verifySecretSalted(secret, stored) {
  if (typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false;
  const parts = stored.split('$');
  if (parts.length !== 3) return false;
  const [, salt, hash] = parts;
  const check = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function looksLegacyHash(stored) {
  return typeof stored === 'string' && stored.length === 64 && /^[0-9a-f]+$/.test(stored);
}
function verifySecretLegacy(secret, stored) {
  const hash = crypto.createHash('sha256').update(String(secret)).digest('hex');
  const a = Buffer.from(hash);
  const b = Buffer.from(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function verifySecret(secret, stored) {
  if (!stored) return false;
  if (looksLegacyHash(stored)) return verifySecretLegacy(secret, stored);
  return verifySecretSalted(secret, stored);
}
function normalizeRecoveryCode(code) {
  return String(code || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}
function staffAuthMethodOf(s) {
  if (!s) return 'pin';
  if (s.authMethod === 'password' || s.authMethod === 'pin') return s.authMethod;
  if (s.password && !s.pin) return 'password';
  return 'pin';
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
  const { staffName, pin, password } = req.body || {};
  if (!staffName) return res.status(400).json({ error: 'staffName is required' });
  if (!pin && !password) return res.status(400).json({ error: 'pin or password is required' });

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

    const method = staffAuthMethodOf(staff);
    let ok = false;
    let upgraded = false;

    if (password) {
      // Password login — only valid if this account uses password
      if (method !== 'password' || !staff.password) {
        recordFailedLogin(staffName);
        return res.status(401).json({ error: 'invalid credentials' });
      }
      ok = verifySecret(password, staff.password);
      if (ok && looksLegacyHash(staff.password)) {
        staff.password = hashSecretSalted(password);
        upgraded = true;
      }
    } else {
      // PIN login
      if (method === 'password' && !staff.pin) {
        recordFailedLogin(staffName);
        return res.status(401).json({ error: 'invalid credentials' });
      }
      if (!staff.pin) {
        recordFailedLogin(staffName);
        return res.status(401).json({ error: 'invalid credentials' });
      }
      ok = verifySecret(pin, staff.pin);
      if (ok && looksLegacyHash(staff.pin)) {
        staff.pin = hashSecretSalted(pin);
        upgraded = true;
      }
    }

    if (!ok) {
      recordFailedLogin(staffName);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    if (upgraded) {
      await pool.query(
        'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
        [clinicData]
      );
    }

    clearFailedLogins(staffName);
    const token = signSession({
      name: staff.name, role: staff.role, owner: !!staff.owner, exp: Date.now() + SESSION_MAX_AGE_MS
    });
    setSessionCookie(req, res, token);
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
    const staff = (rows[0].data.staff || []).map(s => ({
      name: s.name,
      role: s.role,
      owner: !!s.owner,
      authMethod: staffAuthMethodOf(s)
      // never expose pin, password, or recoveryHash
    }));
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
  const { name, role, pin, password, authMethod, recoveryCode } = req.body || {};
  const method = authMethod === 'password' ? 'password' : 'pin';
  if (!name || !role) return res.status(400).json({ error: 'name and role are required' });
  if (method === 'pin' && !pin) return res.status(400).json({ error: 'pin is required' });
  if (method === 'password' && (!password || String(password).length < 6)) {
    return res.status(400).json({ error: 'password (min 6 characters) is required' });
  }
  try {
    const { rows } = await pool.query('SELECT data, version FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    if ((clinicData.staff || []).length > 0) {
      return res.status(403).json({ error: 'setup already completed — ask an existing admin to add your account' });
    }
    const staffRecord = {
      name,
      role,
      authMethod: method,
      owner: true,
      qualification: ''
    };
    if (method === 'pin') staffRecord.pin = hashSecretSalted(pin);
    else staffRecord.password = hashSecretSalted(password);
    if (recoveryCode) {
      staffRecord.recoveryHash = hashSecretSalted(normalizeRecoveryCode(recoveryCode));
    }
    clinicData.staff = [staffRecord];
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    const token = signSession({ name, role, owner: true, exp: Date.now() + SESSION_MAX_AGE_MS });
    setSessionCookie(req, res, token);
    res.json({ ok: true, name, role, owner: true });
  } catch (e) {
    console.error('POST /api/setup failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// Verify a one-time recovery code (shown when the account was created / last reset).
// Does not log the user in — only unlocks the reset-credentials step on the client.
app.post('/api/verify-recovery', async (req, res) => {
  const { staffName, recoveryCode } = req.body || {};
  const code = normalizeRecoveryCode(recoveryCode);
  if (!staffName || code.length < 6) {
    return res.status(400).json({ error: 'staffName and recoveryCode are required' });
  }
  const remainingMs = msLockedFor('recovery:' + staffName);
  if (remainingMs > 0) {
    return res.status(429).json({ error: 'locked', remainingMs });
  }
  try {
    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const staff = (rows[0].data.staff || []).find(s => s.name === staffName);
    if (!staff || !staff.recoveryHash) {
      recordFailedLogin('recovery:' + staffName);
      return res.status(401).json({ error: 'invalid recovery code' });
    }
    const ok = verifySecret(code, staff.recoveryHash);
    if (!ok) {
      recordFailedLogin('recovery:' + staffName);
      return res.status(401).json({ error: 'invalid recovery code' });
    }
    clearFailedLogins('recovery:' + staffName);
    // Short-lived signed token proves recovery was verified for this staff member
    const token = signSession({
      recoveryFor: staff.name,
      exp: Date.now() + 15 * 60 * 1000 // 15 minutes to complete reset
    });
    res.json({ ok: true, recoveryToken: token, name: staff.name });
  } catch (e) {
    console.error('POST /api/verify-recovery failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// After recovery verification (or from a future admin flow), set a new PIN *or* password.
app.post('/api/reset-credentials', async (req, res) => {
  const { staffName, pin, password, authMethod, recoveryCode, recoveryToken } = req.body || {};
  const method = authMethod === 'password' ? 'password' : 'pin';
  if (!staffName) return res.status(400).json({ error: 'staffName is required' });
  if (method === 'pin' && !pin) return res.status(400).json({ error: 'pin is required' });
  if (method === 'password' && (!password || String(password).length < 6)) {
    return res.status(400).json({ error: 'password (min 6 characters) is required' });
  }

  try {
    // Must prove recovery: short-lived token from /api/verify-recovery, or the current recovery code
    let authorized = false;
    if (recoveryToken) {
      const payload = verifySession(recoveryToken);
      if (payload && payload.recoveryFor === staffName && payload.exp > Date.now()) {
        authorized = true;
      }
    }

    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    const staff = (clinicData.staff || []).find(s => s.name === staffName);
    if (!staff) return res.status(404).json({ error: 'staff not found' });

    if (!authorized) {
      const code = normalizeRecoveryCode(recoveryCode);
      if (!code || !staff.recoveryHash || !verifySecret(code, staff.recoveryHash)) {
        return res.status(401).json({ error: 'recovery verification required' });
      }
      authorized = true;
    }

    staff.authMethod = method;
    if (method === 'pin') {
      staff.pin = hashSecretSalted(pin);
      delete staff.password;
    } else {
      staff.password = hashSecretSalted(password);
      delete staff.pin;
    }

    // Rotate recovery secret: client sends a new recovery code in newRecoveryCode
    // (or recoveryCode when authorized via token — frontend uses recoveryCode for the new code)
    const newCodeRaw = (req.body && req.body.newRecoveryCode) || (recoveryToken ? recoveryCode : null);
    if (newCodeRaw) {
      const newCode = normalizeRecoveryCode(newCodeRaw);
      if (newCode.length >= 6) {
        staff.recoveryHash = hashSecretSalted(newCode);
      }
    }

    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    clearFailedLogins(staffName);
    res.json({ ok: true, name: staff.name, authMethod: method });
  } catch (e) {
    console.error('POST /api/reset-credentials failed:', e);
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

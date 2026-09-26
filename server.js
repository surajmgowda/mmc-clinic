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

// ---- TOTP (RFC 6238) for optional admin 2FA ----
function base32DecodeServer(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of cleaned) {
    const val = alphabet.indexOf(c);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function verifyTotp(secretBase32, code) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  const key = base32DecodeServer(secretBase32);
  const now = Date.now();
  for (const delta of [0, -1, 1]) {
    const counter = Math.floor((now + delta * 30000) / 30000);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(counter, 4);
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    const expected = String(bin % 1000000).padStart(6, '0');
    if (expected === c) return true;
  }
  return false;
}

function staffAuthMethodOf(s) {
  if (!s) return 'pin';
  if (s.authMethod === 'password' || s.authMethod === 'pin') return s.authMethod;
  if (s.password && !s.pin) return 'password';
  return 'pin';
}

const STAFF_SECRET_FIELDS = ['pin', 'password', 'recoveryHash', 'totpSecret'];

function sanitizeStaffRecord(s) {
  if (!s || typeof s !== 'object') return s;
  const out = { ...s };
  STAFF_SECRET_FIELDS.forEach(k => { delete out[k]; });
  out.totpEnabled = !!s.totpEnabled;
  out.hasPin = !!s.pin;
  out.hasPassword = !!s.password;
  out.hasRecovery = !!s.recoveryHash;
  return out;
}

function sanitizeClinicData(data) {
  if (!data || typeof data !== 'object') return data;
  const copy = { ...data };
  if (Array.isArray(copy.staff)) copy.staff = copy.staff.map(sanitizeStaffRecord);
  return copy;
}

function mergeStaffSecrets(incomingStaff, currentStaff) {
  const current = Array.isArray(currentStaff) ? currentStaff : [];
  const incoming = Array.isArray(incomingStaff) ? incomingStaff : [];
  const byName = Object.fromEntries(current.map(s => [s.name, s]));
  return incoming.map(s => {
    const prev = byName[s.name];
    if (!prev) {
      const next = { ...s };
      delete next.totpSecret;
      delete next.hasPin;
      delete next.hasPassword;
      delete next.hasRecovery;
      next.totpEnabled = false;
      return next;
    }
    const next = { ...prev, ...s };
    STAFF_SECRET_FIELDS.forEach(k => {
      if (s[k] == null || s[k] === '') next[k] = prev[k];
      else next[k] = s[k];
    });
    next.totpSecret = prev.totpSecret;
    next.totpEnabled = !!prev.totpEnabled;
    delete next.hasPin;
    delete next.hasPassword;
    delete next.hasRecovery;
    return next;
  });
}

function base32EncodeServer(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  }
  return out;
}

function generateTotpSecret() {
  return base32EncodeServer(crypto.randomBytes(20));
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

    // Optional TOTP for accounts that enabled 2FA
    if (staff.totpEnabled && staff.totpSecret) {
      const { totpCode } = req.body || {};
      if (!totpCode) {
        return res.status(401).json({ error: 'totp_required' });
      }
      if (!verifyTotp(staff.totpSecret, totpCode)) {
        recordFailedLogin(staffName);
        return res.status(401).json({ error: 'invalid_totp' });
      }
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
      authMethod: staffAuthMethodOf(s),
      totpEnabled: !!s.totpEnabled
      // never expose pin, password, recoveryHash, or totpSecret
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
    res.json({ data: sanitizeClinicData(rows[0].data), version: rows[0].version });
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
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const current = rows[0];
    if (current.version !== version) {
      return res.status(409).json({ data: sanitizeClinicData(current.data), version: current.version });
    }
    // Non-admin cannot change clinic identity or role permission matrix
    const isOwner = !!(req.staffSession && req.staffSession.owner);
    if (!isOwner && current.data) {
      if (current.data.clinicInfo) data.clinicInfo = current.data.clinicInfo;
      if (current.data.rolePerms) data.rolePerms = current.data.rolePerms;
    }
    // Always restore credential material the GET response deliberately omitted.
    // TOTP secrets are never writable through this document API.
    if (current.data && Array.isArray(data.staff)) {
      data.staff = mergeStaffSecrets(data.staff, current.data.staff);
      if (!isOwner) {
        const byName = Object.fromEntries((current.data.staff || []).map(s => [s.name, s]));
        data.staff = data.staff.map(s => {
          const prev = byName[s.name];
          if (!prev) return s;
          return { ...s, owner: prev.owner, pin: prev.pin, password: prev.password, recoveryHash: prev.recoveryHash };
        });
      }
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

app.post('/api/2fa/setup', requireSession, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    const staff = (clinicData.staff || []).find(s => s.name === req.staffSession.name);
    if (!staff) return res.status(404).json({ error: 'staff not found' });
    if (staff.totpEnabled && staff.totpSecret) {
      return res.status(409).json({ error: 'already_enabled' });
    }
    const secret = generateTotpSecret();
    staff.totpSecret = secret;
    staff.totpEnabled = false;
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    const issuer = encodeURIComponent((clinicData.clinicInfo && clinicData.clinicInfo.shortName) || 'MMC');
    const label = encodeURIComponent(`${issuer}:${staff.name}`);
    const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&digits=6&period=30`;
    res.json({ ok: true, secret, otpauth });
  } catch (e) {
    console.error('POST /api/2fa/setup failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/2fa/enable', requireSession, async (req, res) => {
  const { totpCode } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    const staff = (clinicData.staff || []).find(s => s.name === req.staffSession.name);
    if (!staff || !staff.totpSecret) return res.status(400).json({ error: 'setup_required' });
    if (!verifyTotp(staff.totpSecret, totpCode)) {
      return res.status(401).json({ error: 'invalid_totp' });
    }
    staff.totpEnabled = true;
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    res.json({ ok: true, totpEnabled: true });
  } catch (e) {
    console.error('POST /api/2fa/enable failed:', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/2fa/disable', requireSession, async (req, res) => {
  const { pin, password, totpCode } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT data FROM clinic_store WHERE id = 1');
    if (rows.length === 0) return res.status(500).json({ error: 'store not initialized' });
    const clinicData = rows[0].data;
    const staff = (clinicData.staff || []).find(s => s.name === req.staffSession.name);
    if (!staff) return res.status(404).json({ error: 'staff not found' });
    const method = staffAuthMethodOf(staff);
    let ok = false;
    if (method === 'password') ok = verifySecret(password, staff.password);
    else ok = verifySecret(pin, staff.pin);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    if (staff.totpEnabled && staff.totpSecret) {
      if (!verifyTotp(staff.totpSecret, totpCode)) {
        return res.status(401).json({ error: 'invalid_totp' });
      }
    }
    staff.totpEnabled = false;
    delete staff.totpSecret;
    await pool.query(
      'UPDATE clinic_store SET data = $1, version = version + 1, updated_at = now() WHERE id = 1',
      [clinicData]
    );
    res.json({ ok: true, totpEnabled: false });
  } catch (e) {
    console.error('POST /api/2fa/disable failed:', e);
    res.status(500).json({ error: 'server error' });
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

// MMC Clinic — server.js
// A small Express server that serves the clinic web app and persists
// all clinic data (patients, visits, staff, clinic info) as a single
// JSON document in Postgres, so every device sees the same records.

const express = require('express');
const path = require('path');
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

// ---- API ----
app.get('/api/data', async (req, res) => {
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
app.put('/api/data', async (req, res) => {
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

// ---- Frontend ----
// Single self-contained HTML file (all CSS/JS inline) — served for every
// non-API route.
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

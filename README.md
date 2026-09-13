# MMC Clinic — Male Madeshwara Clinic system

A small web app for running clinic OPD: patient registry, OPD visit notes,
prescriptions, and investigation forms — each printable with the clinic's
letterhead. All data lives in a Postgres database, so every device that
opens the site (reception PC, doctor's laptop, a phone) sees the same
records.

## Environment variables

| Variable       | Required | Purpose                                                              |
|----------------|----------|-----------------------------------------------------------------------|
| `DATABASE_URL` | Yes      | Postgres connection string.                                          |
| `SITE_USER`    | Recommended | Site-wide username (HTTP Basic Auth) shown before the app loads.  |
| `SITE_PASS`    | Recommended | Site-wide password paired with `SITE_USER`.                       |
| `DB_SSL`       | No       | Set to `false` only for a local Postgres that doesn't support SSL.   |
| `PORT`         | No       | Defaults to 3000; hosting platforms usually set this automatically.  |

`SITE_USER`/`SITE_PASS` protect the whole site with one shared password
before anyone reaches the staff PIN screen — worth setting since this app
holds patient health information. Staff PINs (set inside the app, under
Settings) are for day-to-day staff identification, not a strong security
boundary on their own.

## Running locally

```bash
npm install
export DATABASE_URL="postgres://user:pass@host:5432/dbname"
export SITE_USER="mmc"
export SITE_PASS="choose-a-password"
npm start
```

Then open http://localhost:3000 — first run walks you through creating a
staff account.

## Deploying

This is a standard Node.js + Postgres app, so it runs on any host that
offers both (Render, Railway, Fly.io, a VPS, etc.). The steps are always
the same:

1. Create a Postgres database and copy its connection string.
2. Deploy this folder as a Node web service with:
   - Build command: `npm install`
   - Start command: `npm start`
3. Set the environment variables above on the hosting platform.

## Notes and limits

- **Concurrent edits:** if two devices save at almost the same moment,
  the second save is rejected with a "records were just updated" message
  and refreshed with the latest copy, rather than silently overwriting
  the first device's change. Just redo the edit if you see that message.
- **Staff PINs** are stored in the same data document and are meant for
  attributing entries to a staff member, not as strong authentication —
  keep the site-wide password (`SITE_USER`/`SITE_PASS`) as the real gate.
- **Backups:** the app itself doesn't take backups. Whatever Postgres
  provider you use, check what backup/retention it offers and make sure
  it fits how much you'd mind losing.

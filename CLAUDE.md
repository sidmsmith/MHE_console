# MHE Console — Project Instructions

This project follows the global `AGENTS.md` and `SECURITY_BASELINE.md`.
The notes below cover only what's specific to this repository.

## Version identifiers

This project's version appears in three places — keep them in sync:

- `package.json` — the `version` field
- `index.html` — the `<title>` and the `#titleLink` anchor text
  ("MHE Console vX.Y.Z")
- `api/index.py` — the `app_version` value in the status payload

## Local development

This app is two processes running together:

- `node server.js` — Express, serves `index.html` and proxies `/api/*`
  to the Flask backend (port 3000 by default, via `PORT` env var)
- `python api/index.py` — Flask backend, port 5000 (`app.run(debug=True,
  port=5000)`)

In production (Vercel), `server.js` routes `/api/*` requests to
`api/index.py` directly instead of proxying to localhost.

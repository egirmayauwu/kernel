# Kernal Access Lab

A local defensive security-training workspace with three browser environments: Kernal, OmniFrame, and the NEXUS Lab VM. Workbench records and changing telemetry are bundled fixtures. The Help Desk is a scripted, offline keyword matcher backed by a separate JSON index; it does not use a model, call a chat service, or execute commands.

## Project layout

- `server.js` — local Node.js web server and account-service proxy.
- `backend/` — FastAPI account service and SQLite persistence.
- `public/` — launcher, workspaces, Help Desk, and shared browser assets.
- `public/help-index.json` — editable topics, keywords, page descriptions, and saved answers for Help Desk.
- `public/helpdesk.js` — loads the index, matches questions, and displays the saved guidance.
- `requirements.txt` — Python service dependencies.

## Run locally

Requirements: Python 3.10+ and Node.js 18+; the browser application has no npm dependencies.

Install the Python dependencies once:

```powershell
python -m pip install -r requirements.txt
```

In one PowerShell window, start the local account service:

```powershell
python -m uvicorn backend.auth_api:app --host 127.0.0.1 --port 4174
```

In a second window, start the web application from the project root:

```powershell
node server.js
```

Open `http://127.0.0.1:4173`. Create a local account at signup; the account service stores a salted PBKDF2 password hash and hashed session token in SQLite, not plaintext passwords. The default database is in `%USERPROFILE%\.kernal-access-sim\accounts.sqlite3`.

## Help Desk

The Help Desk works without API keys or internet access. It normalizes the question, scores keyword and phrase matches from `public/help-index.json`, and returns a prewritten answer. To add a topic, add an intent with keywords and a response to that index. Page-specific descriptions can be added under `pages`. The Help Desk does not learn from conversations or answer beyond its saved content.

## Workspace boundaries

The bundled tools review fictional records only. They do not scan networks, capture traffic, inspect host files or memory, test credentials, exploit systems, inject code, install persistence, or change operating-system settings. Terminals accept only their displayed local command allowlists and never invoke a host shell. Keep any real security assessment within written authorization and a separately isolated lab.

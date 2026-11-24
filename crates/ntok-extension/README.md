# ntok browser extension

Companion for the ntok web console — it never scans itself (extensions
can't open sockets). It talks to your `ntok-web` server with a Bearer
API token and asks it to scan the current tab's host.

## Load it (developer mode)

- **Chrome/Edge/Brave**: `chrome://extensions` → Developer mode →
  "Load unpacked" → pick this folder.
- **Firefox**: `about:debugging` → "This Firefox" → "Load Temporary
  Add-on" → pick `manifest.json`. (For a permanent install it needs
  signing or Firefox Developer Edition.)

## Connect

1. Run `ntok-web` (or `ntok-desktop`), register an account at
   `/register`.
2. Open the extension's options page (toolbar icon → settings, or
   `chrome://extensions` → ntok → Details → Extension options).
3. Enter the server URL and your account — the password is exchanged
   once for an `ntok_…` API token stored in `chrome.storage.local`.
   Revoke it any time in the web UI under settings → "API access".

## What it does

- Popup → **Scan \<host\>** — posts `{targets, mode:"web", service:true}`
  to `POST /api/scans` and opens the live scan page.
- Links to the console and the search index.

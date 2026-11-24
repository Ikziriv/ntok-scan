# Privacy Policy

**Effective date:** 2026-11-21
**Applies to:** NTOK SCAN (`ntok`, `ntok-web`, `ntok-desktop`, `ntok-extension`, `ntok-mobile`, `ntok-mcp`) and any deployment of it.

## 1. Who is responsible for your data

NTOK SCAN is open-source software that runs on infrastructure you control. Two different situations exist:

- **You run the software yourself** (the normal case). All data the software stores stays on your machine or your own hosting. The upstream project receives nothing — there is no telemetry, no analytics, no crash reporting, and no "phone home" of any kind.
- **You sign in to an instance operated by someone else.** That operator is the data controller for your account. This policy describes what the software stores and transmits so both users and operators know exactly what is involved. Operators should publish their own contact details and any additional policies.

## 2. Data the software stores

All of the following lives in a local SQLite database (`reports/ntok.db`) and report files under `reports/` on the host running the software:

- **Account data** — username, optional display name, email address, and an Argon2id password hash. Plaintext passwords are never stored. If you enable two-factor authentication, a TOTP shared secret is stored.
- **Session and token data** — session cookies' server-side records and any API tokens (`ntok_…`) you mint, each stored hashed or scoped to your account.
- **Authentication audit log** — sign-in successes, failures, lockouts, and the client IP address, written for rate-limiting and account security.
- **Scan data** — targets you scan and everything collected from them: IP addresses, hostnames, open ports, service banners, TLS certificate details, HTTP headers, and derived findings. This data can be sensitive; treat report files as confidential.
- **Settings** — scan defaults, UI preferences, and the AI advisor configuration (endpoint and API key). The API key is never written into reports, exports, or the search index.

## 3. Cookies

The web UI sets exactly one functional cookie: a session token after you sign in (`HttpOnly`, `SameSite`, `Secure` when `NTOK_WEB_COOKIE_SECURE` is on). There are no tracking, advertising, or analytics cookies. Appearance preference is stored in your browser's `localStorage` and never transmitted.

## 4. Optional features that send data off the host

These are all off or unconfigured by default. Data only leaves the host if you (or the instance operator) enable them:

- **Cloudflare D1 mirror** — when `NTOK_D1_*` environment variables are set, scan metadata (targets, ports, services, timestamps — not credentials) is pushed to the configured Cloudflare account so history survives the machine. Cloudflare's own privacy policy applies to that data.
- **AI advisor** — when enabled, target-derived context (hosts, ports, findings, and your question) is sent to the OpenAI-compatible endpoint you configured — for example a remote API or a fully local Ollama. The privacy policy of whichever provider you point it at applies.
- **Passive reconnaissance** — subdomain and certificate-transparency lookups query public third-party services (e.g., crt.sh), which will see the domain you query.
- **External tools** — `masscan`, `nmap`, `nuclei`, `naabu`, `rustscan` and similar binaries run under your control and communicate with your targets directly; their own behavior is governed by their own documentation.

## 5. Third-party sign-in (social login)

The built-in account system is local username/password. If a deployment adds third-party sign-in (OAuth/OIDC providers such as Google, GitHub, Microsoft, Apple, or others):

- We receive only the profile fields the provider shares after your consent — typically a provider account ID, name, email, and avatar URL.
- That identity is linked to a local account record; we do not receive or store your provider password.
- Your use of the provider is governed by that provider's own privacy policy and terms.
- You can disconnect a social identity and use a local password instead, or ask the operator to delete the account entirely.

## 6. Legal bases (EEA/UK users)

Where the GDPR or UK GDPR applies, account and audit data is processed to perform the service you requested (contract) and to secure the service against abuse (legitimate interest). Optional features such as the AI advisor or D1 mirror are used at your direction. Scan data is processed at your instruction; you are responsible for having a lawful basis — authorization — to scan your targets.

## 7. Retention

Data is kept until you delete it. Deleting a scan removes its report from the index; deleting your account removes your credentials, sessions, and tokens. The software offers no automatic expiry because it is your infrastructure — operators of hosted instances should state their own retention schedule.

## 8. Your rights

Because data is local, most rights are self-serve: you can view, export, correct, and delete everything the software holds (scan history, index, account). For hosted instances you may also have the right to access, rectify, erase, restrict, or port your personal data, and to complain to your supervisory authority — contact the instance operator.

## 9. Security

Passwords are hashed with Argon2id, sessions are random tokens, sign-in is rate-limited with per-account lockout, and optional TOTP two-factor authentication is supported. The web UI binds `127.0.0.1` by default. No software can guarantee absolute security; keep report files and `reports/ntok.db` protected — they contain everything your targets exposed.

## 10. Children

The software is a professional security tool and is not directed at children. No age data is collected; operators of hosted instances should not knowingly permit accounts for users under the applicable age of digital consent.

## 11. Changes

Material changes to this policy are committed to this repository and reflected in the "Effective date" above. Continued use after an update constitutes acceptance.

## 12. Contact

- **Privacy/security questions about the software:** open a private report via [GitHub Security Advisories](https://github.com/Ikziriv/ntok-scan/security/advisories/new) or the maintainer channels listed on the repository owner profile.
- **Questions about a hosted instance:** contact the operator of that instance.

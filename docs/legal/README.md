# Legal documents — operator checklist

These documents are professional-quality **templates**, not legal advice.
They are accurate to what the software actually does today (local-first, no
telemetry, opt-in D1 mirror and AI advisor, no built-in OAuth). Before using
them for a real product or hosted service, work through this checklist —
ideally with counsel in your jurisdiction.

## Before you ship

- [ ] **Entity and contact** — Terms §14 and Privacy §12 point at the GitHub
      repo. Replace with your legal entity name, registered address, and a
      privacy contact email if you operate a hosted service.
- [ ] **Governing law** — Terms §13 is deliberately a fill-in. Name a
      jurisdiction and venue (and consider mandatory-arbitration language,
      which varies greatly in enforceability by country).
- [ ] **Social login** — Privacy §5 and Terms §2 cover third-party sign-in
      *conditionally* ("if a deployment adds…"). There is no OAuth code in the
      app today: keep the clauses if you plan to add providers, otherwise
      remove them. When you do add providers, list each one you enable.
- [ ] **Retention** — Privacy §7 says data is kept until deleted. A hosted
      service needs a concrete schedule (account deletion, log rotation,
      backup expiry).
- [ ] **Sub-processors** — if you enable the D1 mirror (Cloudflare) or an AI
      advisor endpoint, list those providers by name in Privacy §4.
- [ ] **Age / audience** — Privacy §10 covers children generically. B2B
      services usually add a "must be 18+" or employment-capacity clause in
      Terms §2.
- [ ] **Consent UX** — registration requires ticking a consent checkbox
      (clickwrap) and the acceptance is audit-logged. Keep that flow; if you
      add marketing email or analytics, they need *separate* opt-ins.
- [ ] **Effective dates** — bump the date on each file when you edit it.

## Regulatory notes

- **GDPR/UK GDPR**: the local-first model means the *operator* is controller;
  the self-serve rights model in §8 works because users hold their own data.
  A hosted instance additionally needs a DPA story and possibly an
  Article 27 EU/UK representative.
- **CCPA/CPRA**: "sale/share" language isn't needed while there is no
  advertising or data sale — keep it that way, or add a notice.
- **Export control**: port scanners are generally uncontrolled, but check
  local rules before distributing into sanctioned jurisdictions.
- **Sector rules**: if you deploy this for clients in finance/health/gov,
  their security-assessment authorization paperwork (rules of engagement)
  matters more than these documents — the AUP §1 defers to it deliberately.

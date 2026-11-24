# Terms of Service

**Effective date:** 2026-11-21

These Terms govern your use of NTOK SCAN — the `ntok` CLI, `ntok-web` interface, desktop, extension, mobile, and MCP surfaces (together, the "Software"). By downloading, installing, registering an account on, or using the Software, you accept these Terms. If you use a hosted instance, the operator's own terms may apply in addition.

## 1. The Software

NTOK SCAN is an open-source network scanner and reconnaissance engine. The source code is licensed under MIT OR Apache-2.0 (see `LICENSE-MIT` / `LICENSE-APACHE`); those licenses govern your rights to copy, modify, and redistribute the code. These Terms govern your *use* of the Software and of any hosted instance of it.

## 2. Eligibility and accounts

Some surfaces (notably `ntok-web`) offer local accounts. You must provide accurate registration information, keep your credentials confidential, and are responsible for everything done under your account. Enable TOTP two-factor authentication for any account reachable beyond your own machine. Notify the operator promptly if you suspect unauthorized access.

**Third-party sign-in.** A deployment may let you register or sign in through a third-party identity provider (Google, GitHub, Microsoft, Apple, or similar OAuth/OIDC provider). Your relationship with that provider is governed by its own terms; we receive only the profile data you consent to share. You remain responsible for activity under the linked account.

## 3. Acceptable use — read this

The Software is a dual-use security tool. The [Acceptable Use Policy](acceptable-use-policy.md) is incorporated into these Terms. Its core rule:

**You may only scan systems you own or have explicit, preferably written, authorization to test.** Unauthorized port scanning, service probing, or vulnerability scanning may violate computer-misuse laws in your jurisdiction (for example the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent laws elsewhere) and the terms of your ISP, hosting provider, and the target's operators. You alone are responsible for determining that your use is lawful and authorized.

Operators of hosted instances may suspend or terminate accounts that violate the Acceptable Use Policy, and may report unlawful use to the relevant providers or authorities.

## 4. Your scan data

Scan results, targets, and reports are your data. You control where they are stored and, if you enable options like the D1 mirror or AI advisor, where they are transmitted. Do not scan, store, or share data about third parties without authorization. Exported reports may contain sensitive details (banners, certificate data, hostnames) — distribute them with the same care as the raw scan.

## 5. AI advisor and external tools

- The optional AI advisor sends target-derived context to the endpoint you configure. Verify that sending that context to that provider is acceptable for your engagement before enabling it.
- The Software can orchestrate third-party tools (`masscan`, `nmap`, `nuclei`, `naabu`, `rustscan`, and others). Those tools run under your control and are governed by their own licenses and terms; you are responsible for installing them legitimately and using them lawfully.

## 6. API access

API tokens (`ntok_…`) you mint grant programmatic access to your account. Keep them secret, scope and rotate them as needed, and revoke any token you suspect is exposed. CI use is permitted within these Terms and the Acceptable Use Policy.

## 7. Feedback and contributions

Bug reports, feature requests, and pull requests are welcome under the repository's contribution terms (`CONTRIBUTING.md`). Do not submit third parties' confidential scan data in public issues; follow `SECURITY.md` for vulnerability reports.

## 8. Disclaimers

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. Scan output is informational reconnaissance — it is not a guarantee that a system is secure, and it is not a substitute for a professional security assessment.

## 9. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE AUTHORS, CONTRIBUTORS, AND OPERATORS OF THE SOFTWARE ARE NOT LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES — OR FOR ANY CLAIM ARISING FROM YOUR SCANNING ACTIVITY, YOUR TARGETS' RESPONSES, ACTIONS BY THIRD PARTIES (INCLUDING ISPs, PROVIDERS, OR AUTHORITIES), OR LOSS OF DATA — ARISING OUT OF OR RELATED TO YOUR USE OF THE SOFTWARE. Where liability cannot be excluded for a hosted instance, it is limited to the amount you paid that operator for the service in the twelve months before the claim, or 100 USD if you paid nothing.

## 10. Indemnification

You agree to indemnify and hold harmless the Software's authors and contributors, and any hosted instance's operator, from claims, damages, and expenses (including reasonable legal fees) arising from your scanning activity, your violation of these Terms or the Acceptable Use Policy, or your violation of any third party's rights.

## 11. Termination

You may stop using the Software and delete your account at any time. Operators may suspend or terminate access for breach of these Terms, for abuse, or where required by law. Sections that by their nature survive (disclaimers, liability, indemnification) survive termination.

## 12. Changes

We may update these Terms by committing changes to this repository; the "Effective date" shows the latest revision. For hosted instances, continued use after notice of a change is acceptance.

## 13. Governing law

These Terms are a template shipped with open-source software. For self-hosted use, the laws of the jurisdiction where the software runs govern, without regard to conflict-of-law rules. An operator offering the Software as a service **must replace this section** with a named governing law and venue appropriate to their entity and users before launching — see `docs/legal/README.md` for the full customization checklist.

## 14. Contact

- **About these Terms:** open an issue or discussion on [github.com/Ikziriv/ntok-scan](https://github.com/Ikziriv/ntok-scan).
- **Security/legal-sensitive reports:** use [GitHub Security Advisories](https://github.com/Ikziriv/ntok-scan/security/advisories/new).

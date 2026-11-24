# Acceptable Use Policy

**Effective date:** 2026-11-21

This policy defines permitted and prohibited use of NTOK SCAN. It is part of the [Terms of Service](terms-of-service.md). NTOK SCAN is a defensive security tool; misuse can violate computer-misuse laws and the rights of network operators.

## 1. The rule

**Scan only systems you own or have explicit authorization to test.** "Authorization" means permission from the system's owner or operator — preferably written (an engagement letter, signed rules-of-engagement, penetration-test contract, bug-bounty scope, or your employer's documented security policy). Verbal assurances and assumed permission are not enough for third-party infrastructure.

Authorization also means staying inside its limits: the targets, ports, techniques, timing, and time windows you were granted — and re-confirming when scope is ambiguous.

## 2. Legitimate uses

- Scanning your own machines, home lab, and networks you administer.
- Authorized security assessments, penetration tests, and red-team engagements within their agreed scope.
- Bug-bounty testing strictly inside the published program scope and rules.
- Inventory, drift tracking, and hygiene checks on infrastructure you are responsible for.
- Scanning public IPs or domains you control to verify your own exposure.

## 3. Prohibited conduct

You must not use the Software to:

- scan, probe, enumerate, or test any system without authorization — including "just checking" someone else's open ports;
- scan targets to locate vulnerabilities for exploitation, extortion, unauthorized access, or data theft;
- deliberately degrade or deny service — aggressive timing templates on fragile or third-party infrastructure, scanning intended to exhaust resources, or ignoring a target's requests to stop;
- evade detection or attribution on networks where you lack authorization (spoofing, relay abuse, scanning from compromised hosts);
- collect, sell, or publish reconnaissance on third parties' systems without their consent;
- violate the acceptable-use terms of networks, ISPs, cloud providers, or upstream services the Software contacts (certificate-transparency logs, subdomain sources, AI endpoints, D1 sync) — their quotas and rules still apply;
- breach any applicable law or regulation in your jurisdiction or the target's.

## 4. Intensity and courtesy

Even authorized scans should be proportionate:

- Use the gentlest timing that meets the need (`-T0`–`-T3`, `--delay-ms`) on production or shared networks; reserve `-T4`/`-T5` for lab or approved windows.
- Respect opt-outs: if an operator asks you to stop, stop — even mid-engagement.
- Keep scope and proof of authorization for each engagement; you may need it if an ISP or provider investigates.

## 5. Hosted instances

Operators of multi-user `ntok-web` deployments should require agreement to this policy at registration, watch for scans aimed at unauthorized third-party space, and may suspend accounts, throttle, or report abuse. Scan traffic originates from the operator's host — operators share responsibility for what their instance is pointed at.

## 6. Reporting abuse

If you believe someone is using NTOK SCAN to target your systems without authorization, gather timestamps, source IPs, and probe characteristics and report it:

- to the operator of the instance the traffic came from, and
- to the project via [GitHub Security Advisories](https://github.com/Ikziriv/ntok-scan/security/advisories/new) or the maintainer channels on the repository owner profile, if the abuse involves the project itself.

Nothing in this policy limits authorized defensive security work — it exists to keep this tool safely in the hands of people doing exactly that.

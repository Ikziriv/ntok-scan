# Security Policy

ntok is a network scanner and reconnaissance tool: it sends probes to target
systems, parses hostile input (banners, TLS certs, HTML, nmap XML), runs
external binaries as subprocesses, and serves a web UI. Treat targets,
report files, watch specs, and web-UI requests as potentially malicious.

ntok itself is dual-use. Only scan systems you own or have written
permission to test.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through [GitHub Security Advisories](../../security/advisories/new)
("Report a vulnerability" on the Security tab). If private reporting is not
enabled or you cannot reach it, contact the maintainer through the channels
listed on the repository owner profile and ask for a private transfer method
before sharing details.

Give the maintainers a reasonable opportunity to investigate and ship a fix
before publishing exploitable details, proof-of-concept code, or weaponized
inputs.

## What to include

- affected ntok version, commit, or release artifact;
- OS, architecture, build profile, and enabled cargo features
  (e.g. `privileged`, `ai`);
- the affected component (`ntok-core` probe/parsers, `ntok-cli`,
  `ntok-web`, `ntok-store`, `tools/` subprocess runner);
- security impact and the access an attacker needs;
- exact reproduction steps — target input, command line, or request;
- expected vs actual behavior;
- crash logs, backtraces, or sanitizer output when applicable;
- whether it reproduces from a clean checkout;
- any known workaround.

Remove credentials, API keys, internal hostnames/IPs, and unrelated system
information from logs before attaching them.

## Malicious test inputs

Do not attach a potentially harmful or non-redistributable target, packet
capture, or report file to a public issue. Describe its format, size, hash,
observed effect, and the command that reproduces the problem; coordinate a
private transfer before sending the sample.

## Scope

Security reports may cover:

- parsing of remote-attacker-controlled data: service banners, TLS
  certificates, HTTP bodies/headers, robots.txt, favicon hashing;
- import parsers (nmap `-oX` XML, ntok JSON reports) and the `reports/`
  file handling around them — path traversal, unsafe overwrite, XXE-style
  expansion, decompression or allocation bombs;
- argument and option handling into `tools/` subprocess invocation
  (`--tools`, `--tool-prefix`, `NTOK_TOOL_*`) — command injection,
  unexpected argument expansion;
- the `ntok-web` HTTP surface — request validation, report/SQLite access,
  the `/search` DSL, scan-form parameters;
- watch-spec (`ntok watch`) and AI-endpoint (`--ai`, `NTOK_AI_*`)
  configuration handling, including where secrets could leak into logs,
  reports, or the index;
- dependency, CI, packaging, and release-artifact integrity.

Out of scope: the fact that ntok scans networks (that is its purpose),
denial-of-service *of a target* caused by aggressive scan timing (use
`-T0..-T2`/`--delay-ms`), and general bugs with no security impact — those
use the normal issue tracker.

## Current limitations

- `ntok-web` binds `127.0.0.1` and has **no authentication**. Any local
  process or user that can reach the port can launch scans and read
  history. Do not expose it on a shared machine or forward the port.
- Scan history (`reports/`) and the index (`reports/ntok.db`) are written
  unencrypted and may contain hostnames, banners, and cert details from
  your targets — treat them as sensitive.
- The AI advisor sends target-derived context (hosts, ports, findings) to
  the configured endpoint. Point it at a local Ollama if that data must
  not leave the machine; the API key is never written to reports or logs.
- External-tool output is trusted once parsed — a compromised or
  look-alike `masscan`/`nmap`/`nuclei`/`naabu`/`rustscan` binary on `PATH`
  (or via `--tool-prefix`) can inject findings into reports.

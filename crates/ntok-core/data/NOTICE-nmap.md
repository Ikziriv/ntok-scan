# Nmap data provenance

`nmap-services` and `nmap-service-probes` are vendored from the nmap
project:

- Source: https://nmap.org / https://svn.nmap.org/nmap/
  (`nmap-services`, `nmap-service-probes`).
- License: Nmap Public Source License (NPSL). These data files remain
  under NPSL — ntok's code is MIT OR Apache-2.0.
- Use here: `nmap-services` provides the port→service-name table;
  the `match`/`softmatch` lines of `nmap-service-probes` provide
  banner→service regexes for `-sV` service detection.
- Refresh: download newer copies from the nmap source tree and replace
  the files verbatim.

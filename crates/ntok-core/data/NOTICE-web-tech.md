# Fingerprint data provenance

`web-tech.json` and `web-cats.json` are vendored from the
community-maintained Wappalyzer fingerprint set:

- Source: https://github.com/enthec/webappanalyzer (`src/technologies/`,
  `src/categories.json`), merged into single files.
- License: GPL-3.0 (this data file only — ntok's code is MIT OR
  Apache-2.0).
- Refresh: download a newer archive of that repo and re-merge the
  `technologies/*.json` files into `web-tech.json`.

`favicon-hashes.json` maps MurmurHash3 favicon hashes (Shodan's
`http.favicon.hash`) to product names:

- Source: projectdiscovery/nuclei-templates
  (`http/technologies/favicon-detect.yaml`), hash/name pairs extracted
  into a single map.
- License: MIT.

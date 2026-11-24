// Shared config + API helper for NTOK SCAN browser extension.
// Credentials live strictly in chrome.storage.local and talk only to the user's server.
const NTOK_KEYS = ["server", "token", "user", "theme", "defaultMode"];

function ntokConfig() {
  return chrome.storage.local.get(NTOK_KEYS).then((cfg) => ({
    server: (cfg.server || "http://127.0.0.1:3000").replace(/\/+$/, ""),
    token: cfg.token || null,
    user: cfg.user || null,
    theme: cfg.theme || "auto",
    defaultMode: cfg.defaultMode || "web",
  }));
}

function ntokApplyTheme(theme) {
  if (!theme || theme === "auto") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

async function ntokApi(path, opts = {}) {
  const { server, token } = await ntokConfig();
  const res = await fetch(server + path, {
    method: opts.method || "GET",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  if (!res.ok) {
    throw new Error(res.status === 401 ? "unauthorized" : `HTTP ${res.status}`);
  }
  return res.json();
}

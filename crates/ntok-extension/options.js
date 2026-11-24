const statusEl = document.getElementById("status");
const formEl = document.getElementById("connect");
const connectedEl = document.getElementById("connected");

async function render() {
  const cfg = await ntokConfig();
  ntokApplyTheme(cfg.theme);
  document.getElementById("server").value = cfg.server;

  const themeInput = document.querySelector(`input[name="theme"][value="${cfg.theme}"]`);
  if (themeInput) themeInput.checked = true;
  const modeInput = document.querySelector(`input[name="defaultMode"][value="${cfg.defaultMode}"]`);
  if (modeInput) modeInput.checked = true;

  if (cfg.user || cfg.token) {
    connectedEl.hidden = false;
    document.getElementById("who").textContent = cfg.user || "API token";
    document.getElementById("console").href = cfg.server + "/";
  } else {
    connectedEl.hidden = true;
  }
}

document.querySelectorAll(".preset").forEach((b) => {
  b.addEventListener("click", () => {
    document.getElementById("server").value = b.dataset.url;
  });
});

document.querySelectorAll('input[name="theme"]').forEach((inp) => {
  inp.addEventListener("change", async () => {
    await chrome.storage.local.set({ theme: inp.value });
    ntokApplyTheme(inp.value);
  });
});

document.querySelectorAll('input[name="defaultMode"]').forEach((inp) => {
  inp.addEventListener("change", async () => {
    await chrome.storage.local.set({ defaultMode: inp.value });
  });
});

formEl.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.className = "msg muted";
  statusEl.textContent = "Verifying connection…";

  const server = document.getElementById("server").value.trim().replace(/\/+$/, "");
  const pastedToken = document.getElementById("token").value.trim();
  const name = document.getElementById("name").value.trim();
  const password = document.getElementById("password").value;

  try {
    if (pastedToken) {
      const res = await fetch(server + "/api/me", {
        headers: { Authorization: `Bearer ${pastedToken}` },
      });
      if (!res.ok) throw new Error(res.status === 401 ? "invalid API token" : `HTTP ${res.status}`);
      const me = await res.json();
      await chrome.storage.local.set({ server, token: pastedToken, user: me.name || "token" });
    } else if (name && password) {
      const res = await fetch(server + "/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, password }),
      });
      if (!res.ok) {
        throw new Error(res.status === 401 ? "wrong username or password" : `HTTP ${res.status}`);
      }
      const out = await res.json();
      await chrome.storage.local.set({ server, token: out.token, user: out.name });
    } else {
      // Try passwordless local server (NTOK_AUTH=off).
      const res = await fetch(server + "/api/me");
      if (!res.ok) throw new Error("enter username & password or paste an API token");
      const me = await res.json();
      await chrome.storage.local.set({ server, token: null, user: me.name || "local" });
    }
    statusEl.className = "msg ok";
    statusEl.textContent = "Connected to " + server;
    document.getElementById("password").value = "";
    document.getElementById("token").value = "";
  } catch (err) {
    statusEl.className = "msg err";
    statusEl.textContent = "Connection failed: " + err.message;
  }
  render();
});

document.getElementById("disconnect").addEventListener("click", async () => {
  await chrome.storage.local.remove(["token", "user"]);
  statusEl.textContent = "";
  render();
});

render();

const mainEl = document.getElementById("main");
const headingEl = document.getElementById("host-heading");

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

async function activeHost() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const u = new URL(tab.url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return { host: u.hostname, origin: u.origin };
  } catch {
    return null;
  }
}

async function render() {
  mainEl.innerHTML = "";
  const cfg = await ntokConfig();
  ntokApplyTheme(cfg.theme);

  document.getElementById("open-console").onclick = () => chrome.tabs.create({ url: cfg.server + "/" });
  document.getElementById("open-index").onclick = () => chrome.tabs.create({ url: cfg.server + "/search" });
  document.getElementById("open-options").onclick = () => chrome.runtime.openOptionsPage();
  document.getElementById("dock-home").onclick = render;

  const target = await activeHost();
  headingEl.textContent = target ? target.host : "NTOK SCAN";

  let me;
  try {
    me = await ntokApi("/api/me");
  } catch (err) {
    const unauth = err.message === "unauthorized";
    mainEl.appendChild(
      el("div", { class: "obs-map" },
        el("div", { class: "obs-top" },
          el("span", { class: "obs-status" },
            el("span", { class: unauth ? "dot warn" : "dot err" }),
            unauth ? "Authentication required" : "Engine offline"
          )
        ),
        el("div", { style: "font-size:12px;color:var(--obs-muted);line-height:1.5" },
          unauth
            ? "Sign in or paste an API token to connect your local NTOK SCAN engine."
            : `Start ntok-web or NTOK SCAN desktop on ${cfg.server}.`
        ),
        el("div", { class: "obs-foot" },
          !unauth ? el("button", { class: "white-pill", onclick: render }, "Retry") : el("span"),
          el("button", { class: "white-pill", onclick: () => chrome.runtime.openOptionsPage() },
            unauth ? "Connect" : "Settings"
          )
        )
      )
    );
    return;
  }

  let selectedMode = cfg.defaultMode || "web";
  const msgEl = el("p", { class: "msg" });

  // Obsidian Telemetry Map Card (Pilo dark map widget)
  const intelBody = el("div", { style: "min-height:44px;font-size:11.5px;color:var(--obs-muted)" },
    target ? "Querying local knowledge index…" : "Open any http(s) site to inspect or scan."
  );
  const obsMap = el("div", { class: "obs-map" },
    el("div", { class: "obs-top" },
      el("span", { class: "obs-status" },
        el("span", { class: "dot ok" }),
        `Engine OK · ${me.name || "local"}`
      ),
      el("span", { class: "mono", style: "font-size:10px;color:var(--accent-sky)" },
        cfg.server.replace(/^https?:\/\//, "")
      )
    ),
    intelBody,
    el("div", { class: "obs-foot" },
      el("span", { class: "mono", style: "font-size:10.5px;color:var(--obs-muted)" },
        target ? "Passive local lookup" : "Standby"
      ),
      el("button", {
        class: "white-pill",
        onclick: () => chrome.tabs.create({
          url: target ? `${cfg.server}/search?q=hostname:${encodeURIComponent(target.host)}` : `${cfg.server}/search`,
        }),
      }, "Inspect")
    )
  );
  mainEl.appendChild(obsMap);

  // Full-width Blue Pill CTA with trailing circular arrow
  const ctaTitle = el("span", { class: "cta-t" }, target ? "Scan target" : "No active host");
  const ctaSub = el("span", { class: "cta-s" },
    target ? `${selectedMode === "web" ? "Website intel" : selectedMode === "net" ? "Port scan" : "Ports + web"} · ${target.host}` : "Switch to a website tab"
  );
  const scanBtn = el("button", {
    class: "cta-pill",
    onclick: async () => {
      if (!target) return;
      scanBtn.disabled = true;
      ctaTitle.textContent = "Launching scan…";
      msgEl.textContent = "";
      try {
        const sendTarget = selectedMode === "web" ? target.origin : target.host;
        const out = await ntokApi("/api/scans", {
          method: "POST",
          body: { targets: sendTarget, mode: selectedMode, service: true, crawl: selectedMode === "net" ? 0 : 2 },
        });
        if (out.error) throw new Error(out.error);
        chrome.tabs.create({ url: cfg.server + out.url });
        window.close();
      } catch (err) {
        msgEl.className = "msg err";
        msgEl.textContent = "Scan failed: " + err.message;
        scanBtn.disabled = false;
        ctaTitle.textContent = "Scan target";
      }
    },
  },
    el("span", {}, ctaTitle, ctaSub),
    el("span", { class: "cta-arr", "aria-hidden": "true" }, "→")
  );
  scanBtn.disabled = !target;
  mainEl.appendChild(scanBtn);

  // Compact mode selector pill
  if (target) {
    const modeSeg = el("div", { class: "seg", style: "margin-top:10px" });
    for (const [val, label] of [["web", "Web intel"], ["net", "Ports"], ["full", "Full"]]) {
      const input = el("input", { type: "radio", name: "mode", value: val });
      if (val === selectedMode) input.checked = true;
      input.addEventListener("change", () => {
        selectedMode = val;
        ctaSub.textContent = `${label} · ${target.host}`;
      });
      modeSeg.appendChild(el("label", {}, input, el("span", {}, label)));
    }
    mainEl.appendChild(modeSeg);
  }
  mainEl.appendChild(msgEl);

  // 2-Tile Bento Row (Pilo "12 Rides" + "★ 320 pts")
  const scansVal = el("div", { class: "v" }, "—");
  const openVal = el("div", { class: "v" }, "—");
  const openLbl = el("div", { class: "k" }, "Indexed ports");
  mainEl.appendChild(
    el("div", { class: "bento-2" },
      el("div", { class: "tile-soft" }, scansVal, el("div", { class: "k" }, "Scans archived")),
      el("div", { class: "tile-dark" }, openVal, openLbl)
    )
  );

  // Hydrate passive host intel + recent scans
  if (target) {
    ntokApi(`/api/host?q=${encodeURIComponent(target.host)}`)
      .then((intel) => {
        intelBody.innerHTML = "";
        if (!intel || (intel.open_ports.length === 0 && intel.technologies.length === 0)) {
          intelBody.textContent = "Not yet in your local index — hit Scan target to map ports & stack.";
          openVal.textContent = "0";
          return;
        }
        openVal.textContent = `${intel.open_ports.length}`;
        if (intel.max_risk >= 40) {
          openLbl.textContent = `Open · risk ${intel.max_risk}`;
        }
        if (intel.open_ports.length > 0) {
          const ports = el("div", { class: "chips", style: "margin-bottom:6px" });
          for (const p of intel.open_ports.slice(0, 6)) {
            ports.appendChild(el("span", { class: "pill sky" }, `${p.port}${p.service ? " " + p.service : ""}`));
          }
          intelBody.appendChild(ports);
        }
        if (intel.technologies.length > 0) {
          const techs = el("div", { class: "chips" });
          for (const t of intel.technologies.slice(0, 5)) {
            techs.appendChild(el("span", { class: "chip-dark" }, t));
          }
          intelBody.appendChild(techs);
        }
      })
      .catch(() => {
        intelBody.textContent = "Ready to scan.";
      });
  }

  ntokApi("/api/scans")
    .then((scans) => {
      if (Array.isArray(scans)) {
        scansVal.textContent = String(scans.length);
        if (!target) {
          const totalOpen = scans.reduce((acc, s) => acc + (s.open || 0), 0);
          openVal.textContent = String(totalOpen);
          openLbl.textContent = "Open ports found";
        }
      }
    })
    .catch(() => {});
}

render();

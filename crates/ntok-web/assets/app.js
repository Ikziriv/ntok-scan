// NTOK SCAN — progressive UI helpers (copy, mode toggle, port
// filter, datatables, provider presets, shortcuts).
(function () {
  var THEME_BG = "#050D24"; // Deep Field canvas — matches --bg
  window._ntokPortFilter = "all";

  function syncNativeChrome() {
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", THEME_BG);
    try {
      if (window.NtokAndroid && typeof window.NtokAndroid.onThemeChanged === "function") {
        window.NtokAndroid.onThemeChanged("night");
      }
    } catch (e) {}
    try {
      if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ntokTheme) {
        window.webkit.messageHandlers.ntokTheme.postMessage("night");
      }
    } catch (e) {}
  }

  var toastTimer = null;
  window.ntokToast = function (msg) {
    var el = document.getElementById("ntok-toast");
    if (!el || !msg) return;
    el.textContent = msg;
    el.classList.add("show");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.classList.remove("show");
    }, 2000);
  };

  // Header menus: close on outside click, Escape, or after picking an item.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      if (!m.contains(e.target) || e.target.closest(".menu-item")) m.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      m.removeAttribute("open");
    });
  });

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(ta);
    return ok;
  }

  window.ntokCopy = function (btn, text) {
    function done() {
      var prev = btn.textContent;
      btn.textContent = "copied";
      btn.classList.add("copied");
      window.ntokToast("Copied to clipboard");
      setTimeout(function () {
        btn.textContent = prev;
        btn.classList.remove("copied");
      }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        if (fallbackCopy(text)) done();
      });
    } else if (fallbackCopy(text)) {
      done();
    }
  };

  // Quick-fill the ports input from a preset chip.
  window.ntokPortPreset = function (v) {
    var p = document.getElementById("ports");
    if (!p) return;
    var val = v === "web" ? "80,443,8080,8443" : v;
    p.value = val;
    p.focus();
    p.dispatchEvent(new Event("change", { bubbles: true }));
    window.ntokToast("Ports set: " + val);
  };

  // AI provider preset cards — fills endpoint + model, marks the card.
  window.ntokProvider = function (el) {
    var ep = document.getElementById("endpoint");
    var md = document.getElementById("model");
    if (ep) ep.value = el.getAttribute("data-endpoint") || "";
    if (md) md.value = el.getAttribute("data-model") || "";
    document.querySelectorAll(".prov-card").forEach(function (c) {
      c.classList.toggle("active", c === el);
    });
  };

  window.ntokPreset = function (sel) {
    var p = {
      deepseek:   ["https://api.deepseek.com/chat/completions", "deepseek-chat"],
      openai:     ["https://api.openai.com/v1/chat/completions", "gpt-4o-mini"],
      openrouter: ["https://openrouter.ai/api/v1/chat/completions", "deepseek/deepseek-chat"],
      ollama:     ["http://localhost:11434/v1/chat/completions", "qwen2.5:3b"]
    }[sel.value];
    if (p) {
      var ep = document.getElementById("endpoint");
      var md = document.getElementById("model");
      if (ep) ep.value = p[0];
      if (md) md.value = p[1];
    }
  };

  window.ntokFilterPorts = function (mode) {
    window._ntokPortFilter = mode;
    applyPortFilter();
  };

  function applyPortFilter() {
    var mode = window._ntokPortFilter || "all";
    document.querySelectorAll(".grid[data-portgrid]").forEach(function (g) {
      g.dataset.filter = mode;
    });
    document.querySelectorAll(".fbtn[data-f]").forEach(function (b) {
      b.classList.toggle("active", b.dataset.f === mode);
    });
  }

  function bindScanMode() {
    var form = document.getElementById("scan-form");
    if (!form) return;
    function sync() {
      var checked = form.querySelector('input[name="mode"]:checked');
      form.dataset.mode = checked ? checked.value : "net";
    }
    form.addEventListener("change", function (e) {
      if (e.target && e.target.name === "mode") sync();
    });
    // Launch-in-flight state: spinner in the CTA arrow, no double submit.
    form.addEventListener("submit", function () {
      var btn = form.querySelector(".cta-pill");
      if (!btn || btn.classList.contains("loading")) return;
      btn.classList.add("loading");
      btn.setAttribute("aria-busy", "true");
      var t = btn.querySelector(".cta-pill-title");
      if (t) t.textContent = "Launching…";
    });
    sync();
  }

  // ---------- Port DataTables (filter / sort / persist across htmx swaps) ----------
  // State lives outside the DOM keyed by .dt#id, so the 750ms live-swap
  // re-renders don't lose the operator's filter or sort.
  var dtState = {};
  function dtGet(id) {
    return dtState[id] || (dtState[id] = { q: "", state: "all", proto: "all", key: null, dir: 1 });
  }
  function stateGroup(s) {
    if (s === "open") return "open";
    if (s === "closed") return "closed";
    return "filtered"; // filtered | open|filtered | unfiltered
  }

  function dtApply(dt) {
    if (!dt || !dt.id) return;
    var st = dtGet(dt.id);
    var inp = dt.querySelector(".dt-search");
    if (inp && inp.value !== st.q) inp.value = st.q;
    dt.querySelectorAll(".dtf").forEach(function (b) {
      b.classList.toggle("active", b.dataset.state === st.state);
    });
    dt.querySelectorAll(".dtp").forEach(function (b) {
      b.classList.toggle("active", b.dataset.proto === st.proto);
    });
    dt.querySelectorAll(".dt-sort").forEach(function (h) {
      h.dataset.dir = st.key === h.dataset.sort ? (st.dir > 0 ? "asc" : "desc") : "";
    });
    var tb = dt.querySelector(".dt-table tbody");
    if (!tb) return;
    var rows = Array.prototype.slice.call(tb.querySelectorAll("tr[data-p]"));
    var info = Array.prototype.slice.call(tb.querySelectorAll("tr.dt-more"));
    if (st.key) {
      var numeric = st.key === "port" || st.key === "rtt";
      rows.sort(function (a, b) {
        var x = a.dataset[st.key], y = b.dataset[st.key], r;
        if (numeric) {
          var fx = parseFloat(x), fy = parseFloat(y);
          if (isNaN(fx) && isNaN(fy)) r = 0;
          else if (isNaN(fx)) r = 1;
          else if (isNaN(fy)) r = -1;
          else r = fx - fy;
        } else {
          r = String(x || "").localeCompare(String(y || ""));
        }
        return r * st.dir;
      });
      rows.forEach(function (r) { tb.appendChild(r); });
      info.forEach(function (r) { tb.appendChild(r); });
    }
    var shown = 0;
    rows.forEach(function (r) {
      var ok = (!st.q || (r.dataset.search || "").indexOf(st.q) >= 0)
        && (st.state === "all" || stateGroup(r.dataset.state) === st.state)
        && (st.proto === "all" || r.dataset.proto === st.proto);
      r.style.display = ok ? "" : "none";
      if (ok) shown++;
    });
    var c = dt.querySelector(".dt-count");
    if (c) c.textContent = "Showing " + shown + " of " + rows.length + " ports";
  }

  function dtApplyAll() {
    document.querySelectorAll(".dt").forEach(dtApply);
  }

  document.addEventListener("input", function (e) {
    if (!e.target || !e.target.classList || !e.target.classList.contains("dt-search")) return;
    var dt = e.target.closest(".dt");
    if (!dt) return;
    dtGet(dt.id).q = e.target.value.trim().toLowerCase();
    dtApply(dt);
  });

  document.addEventListener("click", function (e) {
    var t = e.target.closest ? e.target.closest(".dtf,.dtp,.dt-sort") : null;
    if (!t) return;
    var dt = t.closest(".dt");
    if (!dt) return;
    var st = dtGet(dt.id);
    if (t.classList.contains("dtf")) {
      st.state = t.dataset.state;
    } else if (t.classList.contains("dtp")) {
      st.proto = t.dataset.proto;
    } else {
      var k = t.dataset.sort;
      if (st.key === k) st.dir = -st.dir;
      else { st.key = k; st.dir = 1; }
    }
    dtApply(dt);
  });

  document.addEventListener("DOMContentLoaded", function () {
    bindScanMode();
    applyPortFilter();
    dtApplyAll();
    syncNativeChrome();
  });

  // Preserve chosen port-map filter + datatable state across htmx swaps.
  document.addEventListener("htmx:afterSwap", function () {
    applyPortFilter();
    dtApplyAll();
  });

  // Keyboard shortcuts:
  //   Ctrl/Cmd+K     -> Index search
  //   /              -> Focus primary input (targets, search, or port filter)
  //   Ctrl/Cmd+Enter -> Submit active scan form
  document.addEventListener("keydown", function (e) {
    var tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
    var inField = tag === "input" || tag === "textarea" || tag === "select" || (e.target && e.target.isContentEditable);

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      var q = document.querySelector('input[name="q"]');
      if (q) { q.focus(); q.select(); }
      else { window.location.href = "/search"; }
    } else if (e.key === "/" && !inField && !e.ctrlKey && !e.metaKey && !e.altKey) {
      var target = document.getElementById("targets")
        || document.querySelector('input[name="q"]')
        || document.querySelector(".dt-search");
      if (target) {
        e.preventDefault();
        target.focus();
        target.select();
      }
    } else if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && inField) {
      var form = e.target.closest ? e.target.closest("#scan-form") : null;
      if (form) {
        e.preventDefault();
        if (typeof form.requestSubmit === "function") form.requestSubmit();
        else form.submit();
      }
    }
  });
})();

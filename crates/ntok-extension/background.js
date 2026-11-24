// Right-click "Scan host with NTOK SCAN" on pages and links.
importScripts("api.js");

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "ntok-scan",
    title: "Scan host with NTOK SCAN",
    contexts: ["page", "link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "ntok-scan") return;
  let targetUrl = null;
  try {
    targetUrl = new URL(info.linkUrl || info.pageUrl);
  } catch {
    return;
  }
  if (!targetUrl.hostname) return;
  const cfg = await ntokConfig();
  const mode = cfg.defaultMode || "web";
  const target = mode === "web" ? targetUrl.origin : targetUrl.hostname;
  try {
    const out = await ntokApi("/api/scans", {
      method: "POST",
      body: { targets: target, mode, service: true, crawl: mode === "net" ? 0 : 2 },
    });
    if (!out.error) chrome.tabs.create({ url: cfg.server + out.url });
  } catch {
    chrome.runtime.openOptionsPage();
  }
});

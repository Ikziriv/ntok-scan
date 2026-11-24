//! Optional AI scan advisor: consults an OpenAI-compatible chat endpoint
//! (Ollama, OpenAI, Azure, OpenRouter — anything exposing
//! `/v1/chat/completions`) to adjust the plan before probing and to annotate
//! the report after.
//!
//! `NullAdvisor` is the default — deterministic, no network. The engine only
//! talks to a [`ScanAdvisor`] when the frontend installs one, so scanning
//! never depends on AI being reachable; every advisor failure degrades to a
//! warning, never a scan error.
//!
//! Config (env): `NTOK_AI_ENDPOINT` (default: DeepSeek),
//! `NTOK_AI_MODEL` (default: `deepseek-chat`), `NTOK_AI_KEY`
//! (required when using the default endpoint).

use crate::model::{ScanReport, WebProfile};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.deepseek.com/chat/completions";
const DEFAULT_MODEL: &str = "deepseek-chat";

/// Resolved advisor configuration — env vars, a saved config file, and
/// per-scan UI overrides all converge on this before `HttpAdvisor::new`.
/// Layering: saved settings > env > these defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    /// OpenAI-compatible chat-completions URL.
    pub endpoint: String,
    pub model: String,
    /// Bearer token. Never logged or rendered back to a page.
    pub api_key: Option<String>,
    /// Extra operator instruction appended to advisor prompts.
    pub instructions: Option<String>,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.into(),
            model: DEFAULT_MODEL.into(),
            api_key: None,
            instructions: None,
        }
    }
}

impl AiSettings {
    /// The env layer: `NTOK_AI_*` over the DeepSeek defaults.
    pub fn from_env() -> Self {
        let mut s = Self::default();
        for (var, slot) in [
            ("NTOK_AI_ENDPOINT", &mut s.endpoint),
            ("NTOK_AI_MODEL", &mut s.model),
        ] {
            if let Some(v) = std::env::var(var).ok().filter(|v| !v.trim().is_empty()) {
                *slot = v;
            }
        }
        s.api_key = std::env::var("NTOK_AI_KEY").ok().filter(|v| !v.is_empty());
        s.instructions = std::env::var("NTOK_AI_INSTRUCTIONS")
            .ok()
            .filter(|v| !v.trim().is_empty());
        s
    }

    /// Cheap "would this even connect?" check — no client built, no request.
    /// Only catches the common case (default endpoint with no key); custom
    /// endpoints may still need a key the advisor can't know about.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.api_key.is_none() && self.endpoint == DEFAULT_ENDPOINT {
            return Err("set an API key (AI settings page or NTOK_AI_KEY) — \
                 or use a keyless endpoint"
                .to_string());
        }
        Ok(())
    }
}

/// Snapshot handed to the advisor before probing starts.
#[derive(Debug, Serialize)]
pub struct PlanRequest {
    pub hosts: usize,
    pub ports: usize,
    /// First few ports, so the model sees the shape of the set.
    pub port_sample: Vec<u16>,
    pub technique: &'static str,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
    pub service_probe: bool,
}

/// Adjustments an advisor may suggest. All fields optional; the engine
/// clamps and applies only what is present.
#[derive(Debug, Default)]
pub struct PlanAdvice {
    /// Replace the port set (e.g. focus on likely-relevant ports).
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout: Option<Duration>,
    /// Free-text rationale; surfaced as a `ScanEvent::Note`.
    pub rationale: Option<String>,
}

/// The "AI" seam. Frontends install `Arc<dyn ScanAdvisor>` on
/// `ScanConfig::advisor`; both hooks may return nothing.
pub trait ScanAdvisor: Send + Sync {
    /// Called once after target expansion, before host discovery.
    fn plan<'a>(
        &'a self,
        req: &'a PlanRequest,
    ) -> Pin<Box<dyn Future<Output = PlanAdvice> + Send + 'a>>;

    /// Called once after the report is built. Return commentary text, or
    /// `None` to say nothing.
    fn analyze<'a>(
        &'a self,
        report: &'a ScanReport,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>;

    /// Called once per web profile, after technology fingerprinting.
    /// Return a short stack commentary, or `None` to stay quiet.
    fn analyze_web<'a>(
        &'a self,
        _profile: &'a WebProfile,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

/// Default advisor: no suggestions, no commentary, no network.
pub struct NullAdvisor;

impl ScanAdvisor for NullAdvisor {
    fn plan<'a>(
        &'a self,
        _req: &'a PlanRequest,
    ) -> Pin<Box<dyn Future<Output = PlanAdvice> + Send + 'a>> {
        Box::pin(async { PlanAdvice::default() })
    }

    fn analyze<'a>(
        &'a self,
        _report: &'a ScanReport,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

#[cfg(feature = "ai")]
pub use http::HttpAdvisor;
#[cfg(not(feature = "ai"))]
pub use stub::HttpAdvisor;

#[cfg(feature = "ai")]
mod http {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    const ADVISOR_TIMEOUT: Duration = Duration::from_secs(20);

    /// OpenAI-compatible chat-completions backend.
    pub struct HttpAdvisor {
        endpoint: String,
        api_key: Option<String>,
        model: String,
        instructions: Option<String>,
        client: reqwest::Client,
        /// One-shot breaker: first transport failure disables the advisor for
        /// the rest of the scan, so a dead endpoint costs one timeout, not two.
        dead: AtomicBool,
    }

    impl HttpAdvisor {
        /// Build from resolved settings. `Err` explains what to fix — callers
        /// should print it and fall back to [`NullAdvisor`].
        pub fn new(settings: AiSettings) -> std::result::Result<Self, String> {
            settings.validate()?;
            crate::ensure_crypto_provider();
            let client = reqwest::Client::builder()
                .timeout(ADVISOR_TIMEOUT)
                .build()
                .map_err(|e| e.to_string())?;
            Ok(Self {
                endpoint: settings.endpoint,
                api_key: settings.api_key.filter(|k| !k.is_empty()),
                model: settings.model,
                instructions: settings.instructions.filter(|i| !i.trim().is_empty()),
                client,
                dead: AtomicBool::new(false),
            })
        }

        /// Build from env — kept for the CLI; the web UI loads
        /// [`AiSettings`] from its config file instead.
        pub fn from_env() -> std::result::Result<Self, String> {
            Self::new(AiSettings::from_env())
        }

        /// Connectivity probe for the settings page. Unlike [`chat`], errors
        /// are reported, not swallowed.
        pub async fn test(&self) -> std::result::Result<String, String> {
            let body = serde_json::json!({
                "model": self.model,
                "stream": false,
                "max_tokens": 8,
                "temperature": 0.0,
                "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
            });
            let mut req = self.client.post(&self.endpoint).json(&body);
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| format!("request failed: {e}"))?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| e.to_string())?;
            if !status.is_success() {
                let body: String = text.chars().take(200).collect();
                return Err(format!("HTTP {status}: {body}"));
            }
            let json: serde_json::Value = serde_json::from_str(&text)
                .map_err(|_| "endpoint returned non-JSON".to_string())?;
            json.pointer("/choices/0/message/content")
                .and_then(|c| c.as_str())
                .map(|s| s.chars().take(80).collect())
                .ok_or_else(|| "endpoint replied but not in chat-completions shape".to_string())
        }

        /// Translate a natural-language question into an `ntok search`
        /// query string — the model writes `field:value` DSL, the caller
        /// parses it like user input. `None` on any failure; the CLI
        /// falls back to treating the input as a literal query.
        pub async fn translate_query(&self, question: &str) -> Option<String> {
            const SYSTEM: &str = "You translate natural-language questions into \
                ntok search queries. Reply with ONLY the query string — no \
                prose, no backticks, no explanation. Query syntax: field:value \
                terms AND'd together, bare words do full-text search. Fields: \
                ip:<exact> net:<prefix> port:<n|a-b> protocol:<tcp|udp> state:<open> \
                service:<name> product:<name> banner:<text> hostname:<name> \
                os:<name> asn:<n> org:<name> server:<name> tech:<name> \
                status:<http-code> has:<banner|tls|web|tech|hostname|os|org|asn> \
                expired:<true> selfsigned:<true> risk:<high|medium|low|n> \
                anomaly:<high|medium|low|n> favicon:<mmh3-hash> \
                after:<unix|YYYY-MM-DD> before:<unix|YYYY-MM-DD>. \
                Example: 'expired certs in the lab net' -> \
                net:10. has:tls expired:true";
            let text = self.chat(SYSTEM, question).await?;
            // First non-empty line, fenced blocks unwrapped, surrounding
            // quotes/backticks trimmed — models can't resist a preamble.
            let line = text
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("```"))?;
            Some(line.trim_matches(['"', '\'', '`']).to_string())
        }

        async fn chat(&self, system: &str, user: &str) -> Option<String> {
            if self.dead.load(Ordering::Relaxed) {
                return None;
            }
            let sys;
            let system = match &self.instructions {
                Some(i) => {
                    sys = format!("{system}\n\nOperator instructions: {i}");
                    sys.as_str()
                }
                None => system,
            };
            let body = serde_json::json!({
                "model": self.model,
                "stream": false,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            });
            let mut req = self.client.post(&self.endpoint).json(&body);
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(_) => {
                    self.dead.store(true, Ordering::Relaxed);
                    return None;
                }
            };
            let json: serde_json::Value = resp.json().await.ok()?;
            json.pointer("/choices/0/message/content")?
                .as_str()
                .map(str::to_string)
        }
    }

    #[derive(Deserialize)]
    struct AdviceJson {
        ports: Option<Vec<u16>>,
        concurrency: Option<usize>,
        timeout_ms: Option<u64>,
        rationale: Option<String>,
    }

    impl ScanAdvisor for HttpAdvisor {
        fn plan<'a>(
            &'a self,
            req: &'a PlanRequest,
        ) -> Pin<Box<dyn Future<Output = PlanAdvice> + Send + 'a>> {
            Box::pin(async move {
                let Ok(plan) = serde_json::to_string(req) else {
                    return PlanAdvice::default();
                };
                let Some(text) = self
                    .chat(
                        "You are the scan planner inside ntok, an nmap-style \
                         Rust port scanner. Given a scan plan as JSON, reply with a \
                         JSON object only — no markdown, no prose:\n\
                         {\"ports\":[u16,...]|null,\"concurrency\":int|null,\
                         \"timeout_ms\":int|null,\"rationale\":string|null}\n\
                         ports: pick 1-65535 focused on services likely relevant \
                         to this scan; null keeps the requested set.\n\
                         concurrency: 1-4096. timeout_ms: 100-10000. \
                         rationale: one sentence.",
                        &plan,
                    )
                    .await
                else {
                    return PlanAdvice::default();
                };
                let Some(blob) = extract_json(&text) else {
                    tracing::warn!("advisor: non-JSON plan response");
                    return PlanAdvice::default();
                };
                let Ok(parsed) = serde_json::from_str::<AdviceJson>(blob) else {
                    tracing::warn!("advisor: unparseable plan response");
                    return PlanAdvice::default();
                };
                PlanAdvice {
                    ports: parsed.ports.map(|p| {
                        p.into_iter()
                            .filter(|p| *p != 0)
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect()
                    }),
                    concurrency: parsed.concurrency,
                    timeout: parsed.timeout_ms.map(Duration::from_millis),
                    rationale: parsed.rationale.filter(|r| !r.trim().is_empty()),
                }
            })
        }

        fn analyze<'a>(
            &'a self,
            report: &'a ScanReport,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async move {
                // Compact summary — full reports can be megabytes.
                let findings: Vec<serde_json::Value> = report
                    .hosts
                    .iter()
                    .filter_map(|h| {
                        let open: Vec<serde_json::Value> = h
                            .ports
                            .iter()
                            .filter(|p| p.state.is_open())
                            .map(|p| {
                                serde_json::json!({
                                    "port": p.port,
                                    "proto": p.protocol.as_str(),
                                    "service": p.service,
                                })
                            })
                            .collect();
                        (!open.is_empty()).then(|| serde_json::json!({"ip": h.ip, "open": open}))
                    })
                    .take(40)
                    .collect();
                let summary = serde_json::json!({
                    "hosts_up": report.summary.hosts_up,
                    "hosts_down": report.summary.hosts_down,
                    "open": report.summary.open,
                    "filtered": report.summary.filtered,
                    "elapsed_secs": report.elapsed_secs,
                    "findings": findings,
                })
                .to_string();
                self.chat(
                    "You are a network analyst reviewing an nmap-style scan \
                     report. Reply in plain text, 2-4 sentences: the most \
                     notable exposed services, what the hosts probably are, \
                     and one concrete risk or follow-up. No preamble.",
                    &summary,
                )
                .await
            })
        }

        fn analyze_web<'a>(
            &'a self,
            p: &'a WebProfile,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async move {
                if p.technologies.is_empty() && p.status == 0 {
                    return None;
                }
                // Compact stack summary — profiles carry megabytes of assets.
                let techs: Vec<serde_json::Value> = p
                    .technologies
                    .iter()
                    .take(30)
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "version": t.version,
                            "confidence": t.confidence,
                        })
                    })
                    .collect();
                let summary = serde_json::json!({
                    "url": p.final_url,
                    "status": p.status,
                    "server": p.server,
                    "powered_by": p.powered_by,
                    "security_headers_score": p.security.score,
                    "technologies": techs,
                    "company": p.company.names,
                    "asn": p.company.asn,
                    "external_domains": p.external_domains.iter().take(12).collect::<Vec<_>>(),
                    "api_hints": p.api_hints.iter().take(10).collect::<Vec<_>>(),
                    "tls": p.tls.as_ref().map(|t| serde_json::json!({
                        "issuer": t.issuer_org,
                        "expired": t.expired,
                        "self_signed": t.self_signed,
                    })),
                })
                .to_string();
                self.chat(
                    "You are a web-stack analyst inside ntok. Given a \
                     technology profile as JSON, reply in plain text, 2-4 \
                     sentences: what the stack is, what kind of site it \
                     likely is, and one notable observation — outdated or \
                     surprising technology, weak security headers, unusual \
                     infrastructure. No preamble.",
                    &summary,
                )
                .await
            })
        }
    }

    /// Pull the first `{...}` span out of a model reply — models like to wrap
    /// JSON in prose or ```json fences.
    fn extract_json(text: &str) -> Option<&str> {
        let start = text.find('{')?;
        let end = text.rfind('}')?;
        (end > start).then(|| &text[start..=end])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn extracts_json_from_wrapped_reply() {
            assert_eq!(extract_json("{\"a\":1}"), Some("{\"a\":1}"));
            assert_eq!(
                extract_json("Here you go:\n```json\n{\"a\":1}\n```"),
                Some("{\"a\":1}")
            );
            assert_eq!(extract_json("no json"), None);
        }
    }
}

#[cfg(not(feature = "ai"))]
mod stub {
    use super::*;

    /// Exists so frontends compile regardless of the `ai` feature; `new`
    /// always errors explaining the missing feature.
    pub struct HttpAdvisor;

    impl HttpAdvisor {
        pub fn new(_: AiSettings) -> std::result::Result<Self, String> {
            Err("ntok-core built without the `ai` feature".to_string())
        }

        pub fn from_env() -> std::result::Result<Self, String> {
            Self::new(AiSettings::from_env())
        }

        pub async fn test(&self) -> std::result::Result<String, String> {
            Err("ntok-core built without the `ai` feature".to_string())
        }

        pub async fn translate_query(&self, _question: &str) -> Option<String> {
            None
        }
    }

    impl ScanAdvisor for HttpAdvisor {
        fn plan<'a>(
            &'a self,
            _req: &'a PlanRequest,
        ) -> Pin<Box<dyn Future<Output = PlanAdvice> + Send + 'a>> {
            Box::pin(async { PlanAdvice::default() })
        }

        fn analyze<'a>(
            &'a self,
            _report: &'a ScanReport,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async { None })
        }
    }
}

/// Shared default for `ScanConfig`.
pub fn null_advisor() -> Arc<dyn ScanAdvisor> {
    Arc::new(NullAdvisor)
}

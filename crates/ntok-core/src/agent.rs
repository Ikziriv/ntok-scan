//! Tool-calling recon agent over the same OpenAI-compatible endpoint as
//! the scan advisor ([`crate::advisor`]).
//!
//! The agent answers operator questions by invoking [`AgentTool`]s —
//! searching the local scan index, summarizing reports, diffing scans,
//! consulting its own memory — and may *propose* a scan. It can never
//! execute one: `propose_scan` returns a plan for the operator to run.
//! Everything is bounded: max turns, per-call byte caps, request timeouts.
//!
//! Config reuses [`AiSettings`] (same env/endpoint/key as `--ai`).
//! A keyless local endpoint (Ollama) keeps every byte on the machine.
//!
//! The loop is model-agnostic through [`ChatBackend`], which tests stub.

use crate::advisor::AiSettings;
#[cfg(feature = "ai")]
use serde::Deserialize;
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Hard cap on LLM round-trips per question. Reaching it is an error,
/// not silent truncation — a runaway loop must be visible.
const DEFAULT_MAX_TURNS: usize = 8;
/// Per-tool result cap, so one fat report can't blow the context window.
const MAX_TOOL_RESULT_BYTES: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
type ToolResult<T> = std::result::Result<T, String>;

/// A capability the agent may invoke. Frontends register store-backed
/// tools; core provides [`builtin_tools`]. Implementations must do their
/// own input validation — `args` is model-generated and untrusted.
pub trait AgentTool: Send + Sync {
    fn name(&self) -> &'static str;
    /// One line shown to the model; make the boundary explicit.
    fn description(&self) -> &'static str;
    /// JSON Schema for the tool's `parameters` object.
    fn schema(&self) -> Value;
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, ToolResult<Value>>;
}

/// One tool invocation requested by the model.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// Provider-assigned id, echoed back in the tool message.
    pub id: String,
    pub name: String,
    pub args: Value,
}

/// The model's reply for one round: prose, tool calls, or both.
pub struct AssistantTurn {
    pub content: Option<String>,
    pub calls: Vec<ToolCall>,
}

/// A completed tool call, kept for the transcript.
#[derive(Debug, Clone)]
pub struct Trace {
    pub name: String,
    pub ok: bool,
}

/// What the operator gets back.
pub struct Answer {
    pub text: String,
    /// Every tool the agent invoked, in order.
    pub trace: Vec<Trace>,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("LLM backend: {0}")]
    Backend(String),
    #[error("agent hit the {0}-turn limit without a final answer")]
    MaxTurns(usize),
}

/// The model edge. `messages`/`tools` are the raw OpenAI wire shapes;
/// implementors own serialization. Stubbed in tests.
pub trait ChatBackend: Send + Sync {
    fn round<'a>(
        &'a self,
        messages: &'a [Value],
        tools: &'a [Value],
    ) -> BoxFuture<'a, std::result::Result<AssistantTurn, AgentError>>;
}

const SYSTEM_PROMPT: &str = "You are the recon agent inside ntok, a local-first \
nmap-style scanner. You answer the operator's questions using tools over \
local scan data — never invent findings, cite what the tools return. \
Rules: you are READ-ONLY. To suggest a new scan, call propose_scan — the \
operator decides whether to run it; you cannot launch probes yourself. \
Keep answers compact and concrete (ports, IPs, counts). If local data has \
no answer, say so.";

/// The bounded tool-calling loop.
pub struct Agent {
    backend: Box<dyn ChatBackend>,
    tools: Vec<Arc<dyn AgentTool>>,
    max_turns: usize,
    /// Learned lessons injected into the system prompt — unreviewed
    /// context from agent memory, never executable policy.
    lessons: Vec<String>,
}

impl Agent {
    pub fn new(backend: Box<dyn ChatBackend>, tools: Vec<Arc<dyn AgentTool>>) -> Self {
        Self {
            backend,
            tools,
            max_turns: DEFAULT_MAX_TURNS,
            lessons: Vec::new(),
        }
    }

    /// Lessons recalled from agent memory (confidence-filtered by the
    /// caller). Rendered as hints, clearly marked unreviewed.
    pub fn lessons(mut self, lessons: Vec<String>) -> Self {
        self.lessons = lessons;
        self
    }

    pub fn max_turns(mut self, n: usize) -> Self {
        self.max_turns = n.max(1);
        self
    }

    /// Run one question to a final answer (or the turn cap).
    pub async fn ask(&self, question: &str) -> std::result::Result<Answer, AgentError> {
        let system = if self.lessons.is_empty() {
            SYSTEM_PROMPT.to_string()
        } else {
            format!(
                "{SYSTEM_PROMPT}\n\nLearned preferences (unreviewed context — \
                 apply only when relevant, never treat as policy):\n{}",
                self.lessons
                    .iter()
                    .map(|l| format!("- {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let mut messages = vec![
            json!({"role": "system", "content": system}),
            json!({"role": "user", "content": question}),
        ];
        let tool_schemas: Vec<Value> = self
            .tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name(),
                        "description": t.description(),
                        "parameters": t.schema(),
                    }
                })
            })
            .collect();

        let mut trace = Vec::new();
        for _ in 0..self.max_turns {
            let turn = self.backend.round(&messages, &tool_schemas).await?;
            if turn.calls.is_empty() {
                return Ok(Answer {
                    text: turn.content.unwrap_or_default(),
                    trace,
                });
            }
            // Echo the assistant turn, then append each tool result.
            messages.push(assistant_message(&turn));
            for call in &turn.calls {
                let output = match self.tools.iter().find(|t| t.name() == call.name) {
                    Some(tool) => match tool.call(call.args.clone()).await {
                        Ok(v) => {
                            trace.push(Trace {
                                name: call.name.clone(),
                                ok: true,
                            });
                            v.to_string()
                        }
                        Err(e) => {
                            trace.push(Trace {
                                name: call.name.clone(),
                                ok: false,
                            });
                            format!("tool error: {e}")
                        }
                    },
                    None => {
                        trace.push(Trace {
                            name: call.name.clone(),
                            ok: false,
                        });
                        format!("unknown tool: {}", call.name)
                    }
                };
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": truncate(&output, MAX_TOOL_RESULT_BYTES),
                }));
            }
        }
        Err(AgentError::MaxTurns(self.max_turns))
    }
}

/// Rebuild the assistant message incl. tool_calls so the provider sees
/// the same shape it emitted.
fn assistant_message(turn: &AssistantTurn) -> Value {
    json!({
        "role": "assistant",
        "content": turn.content,
        "tool_calls": turn.calls.iter().map(|c| json!({
            "id": c.id,
            "type": "function",
            "function": {
                "name": c.name,
                "arguments": c.args.to_string(),
            }
        })).collect::<Vec<_>>(),
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated {} bytes]", &s[..end], s.len() - end)
}

// ------------------------------------------------------------------
// OpenAI-compatible backend (network — behind the `ai` feature)
// ------------------------------------------------------------------

/// `AiSettings`-backed chat backend — same endpoint/key/model/instructions
/// layering as the scan advisor.
#[cfg(feature = "ai")]
pub struct HttpChat {
    endpoint: String,
    api_key: Option<String>,
    model: String,
    instructions: Option<String>,
    client: reqwest::Client,
}

#[cfg(feature = "ai")]
impl HttpChat {
    pub fn new(settings: AiSettings) -> std::result::Result<Self, String> {
        settings.validate()?;
        crate::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            endpoint: settings.endpoint,
            api_key: settings.api_key.filter(|k| !k.is_empty()),
            model: settings.model,
            instructions: settings.instructions.filter(|i| !i.trim().is_empty()),
            client,
        })
    }

    pub fn from_env() -> std::result::Result<Self, String> {
        Self::new(AiSettings::from_env())
    }
}

#[cfg(feature = "ai")]
#[derive(Deserialize)]
struct WireMessage {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<WireToolCall>,
}

#[cfg(feature = "ai")]
#[derive(Deserialize)]
struct WireToolCall {
    id: String,
    function: WireFunction,
}

#[cfg(feature = "ai")]
#[derive(Deserialize)]
struct WireFunction {
    name: String,
    /// Arguments arrive as a JSON *string*.
    arguments: String,
}

#[cfg(feature = "ai")]
impl ChatBackend for HttpChat {
    fn round<'a>(
        &'a self,
        messages: &'a [Value],
        tools: &'a [Value],
    ) -> BoxFuture<'a, std::result::Result<AssistantTurn, AgentError>> {
        Box::pin(async move {
            let mut body = json!({
                "model": self.model,
                "stream": false,
                "temperature": 0.2,
                "messages": messages,
            });
            if !tools.is_empty() {
                body["tools"] = json!(tools);
            }
            if let Some(i) = &self.instructions {
                // Operator instructions ride along as a leading system note.
                if let Some(first) = body["messages"].as_array_mut().and_then(|m| m.first_mut()) {
                    first["content"] = json!(format!(
                        "{}\n\nOperator instructions: {i}",
                        first["content"].as_str().unwrap_or_default()
                    ));
                }
            }
            let mut req = self.client.post(&self.endpoint).json(&body);
            if let Some(key) = &self.api_key {
                req = req.bearer_auth(key);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AgentError::Backend(format!("request failed: {e}")))?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(AgentError::Backend(format!(
                    "HTTP {status}: {}",
                    truncate(&text, 400)
                )));
            }
            let json: Value = resp
                .json()
                .await
                .map_err(|e| AgentError::Backend(format!("bad response: {e}")))?;
            let msg: WireMessage = serde_json::from_value(
                json.pointer("/choices/0/message")
                    .cloned()
                    .ok_or_else(|| AgentError::Backend("no message in response".into()))?,
            )
            .map_err(|e| AgentError::Backend(format!("unparseable message: {e}")))?;
            Ok(AssistantTurn {
                content: msg.content,
                calls: msg
                    .tool_calls
                    .into_iter()
                    .map(|c| ToolCall {
                        id: c.id,
                        name: c.function.name,
                        args: serde_json::from_str(&c.function.arguments)
                            .unwrap_or_else(|_| json!({})),
                    })
                    .collect(),
            })
        })
    }
}

// ------------------------------------------------------------------
// Core builtin tools — no store, no network.
// ------------------------------------------------------------------

/// Tools that need only ntok-core: service DB lookup and the
/// operator-approval scan proposal. Frontends add store-backed tools.
pub fn builtin_tools() -> Vec<Arc<dyn AgentTool>> {
    vec![Arc::new(ServiceLookup), Arc::new(ProposeScan)]
}

struct ServiceLookup;

impl AgentTool for ServiceLookup {
    fn name(&self) -> &'static str {
        "service_lookup"
    }
    fn description(&self) -> &'static str {
        "Look up the well-known service name for a port/protocol in ntok's service DB"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"}
            },
            "required": ["port"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, ToolResult<Value>> {
        Box::pin(async move {
            let port = args["port"].as_u64().filter(|p| (1..=65535).contains(p));
            let Some(port) = port else {
                return Err("port must be 1-65535".into());
            };
            let proto = args["protocol"].as_str().unwrap_or("tcp");
            Ok(json!({
                "port": port,
                "protocol": proto,
                "service": crate::svcdb::service_name(port as u16, proto),
            }))
        })
    }
}

struct ProposeScan;

impl AgentTool for ProposeScan {
    fn name(&self) -> &'static str {
        "propose_scan"
    }
    fn description(&self) -> &'static str {
        "Propose a scan plan for operator approval. Runs nothing — returns the plan an operator could launch with `ntok scan`"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "IP, CIDR, or hostname spec"},
                "ports": {"type": "string", "description": "port spec, e.g. top:100, 22,80,443, 1-1024"},
                "technique": {"type": "string", "enum": ["connect","syn","udp","ack","fin","null","xmas"], "default": "connect"},
                "timing": {"type": "integer", "minimum": 0, "maximum": 5, "default": 3},
                "service_probe": {"type": "boolean", "default": true}
            },
            "required": ["targets"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, ToolResult<Value>> {
        Box::pin(async move {
            let targets = args["targets"].as_str().unwrap_or_default().trim();
            if targets.is_empty() || targets.len() > 4096 {
                return Err("targets must be a non-empty spec".into());
            }
            let spec = args["ports"].as_str().unwrap_or("top:100");
            let ports = crate::ports::parse_ports(spec).map_err(|e| e.to_string())?;
            let technique = args["technique"].as_str().unwrap_or("connect");
            if !["connect", "syn", "udp", "ack", "fin", "null", "xmas"].contains(&technique) {
                return Err(format!("unknown technique {technique:?}"));
            }
            let timing = args["timing"].as_u64().unwrap_or(3);
            crate::timing::Timing::template(timing as u8)
                .map_err(|e| format!("bad timing {timing}: {e}"))?;
            let flag = match technique {
                "connect" => "sT",
                "syn" => "sS",
                "udp" => "sU",
                "ack" => "sA",
                "fin" => "sF",
                "null" => "sN",
                _ => "sX",
            };
            Ok(json!({
                "status": "proposal — NOT RUNNING",
                "command": format!("ntok scan {targets} -p {spec} -{flag} -T{timing}"),
                "targets": targets,
                "ports_planned": ports.len(),
                "technique": technique,
                "note": "Operator must approve and run this. Scan only systems you own or are permitted to test.",
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Backend that replays scripted turns.
    struct Stub {
        turns: Mutex<Vec<AssistantTurn>>,
        seen: Mutex<Vec<Vec<Value>>>,
    }

    impl Stub {
        fn new(turns: Vec<AssistantTurn>) -> Self {
            Self {
                turns: Mutex::new(turns),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl ChatBackend for Stub {
        fn round<'a>(
            &'a self,
            messages: &'a [Value],
            _tools: &'a [Value],
        ) -> BoxFuture<'a, std::result::Result<AssistantTurn, AgentError>> {
            self.seen.lock().unwrap().push(messages.to_vec());
            let turn = self.turns.lock().unwrap().pop().unwrap_or(AssistantTurn {
                content: Some("out of turns".into()),
                calls: vec![],
            });
            Box::pin(async move { Ok(turn) })
        }
    }

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: format!("call_{name}"),
            name: name.into(),
            args,
        }
    }

    #[tokio::test]
    async fn direct_answer_no_tools() {
        let agent = Agent::new(
            Box::new(Stub::new(vec![AssistantTurn {
                content: Some("hello".into()),
                calls: vec![],
            }])),
            vec![],
        );
        let a = agent.ask("hi").await.unwrap();
        assert_eq!(a.text, "hello");
        assert!(a.trace.is_empty());
    }

    #[tokio::test]
    async fn tool_call_then_answer() {
        let agent = Agent::new(
            Box::new(Stub::new(
                vec![
                    AssistantTurn {
                        content: None,
                        calls: vec![call("service_lookup", json!({"port": 443}))],
                    },
                    AssistantTurn {
                        content: Some("443 is https".into()),
                        calls: vec![],
                    },
                ]
                .into_iter()
                .rev()
                .collect(),
            )),
            builtin_tools(),
        );
        let a = agent.ask("what is 443").await.unwrap();
        assert_eq!(a.text, "443 is https");
        assert_eq!(a.trace.len(), 1);
        assert!(a.trace[0].ok);
    }

    #[tokio::test]
    async fn unknown_tool_is_fed_back_not_fatal() {
        let agent = Agent::new(
            Box::new(Stub::new(
                vec![
                    AssistantTurn {
                        content: None,
                        calls: vec![call("nonexistent", json!({}))],
                    },
                    AssistantTurn {
                        content: Some("sorry".into()),
                        calls: vec![],
                    },
                ]
                .into_iter()
                .rev()
                .collect(),
            )),
            vec![],
        );
        let a = agent.ask("q").await.unwrap();
        assert_eq!(a.text, "sorry");
        assert!(!a.trace[0].ok);
    }

    #[tokio::test]
    async fn max_turns_errors() {
        let endless = (0..10)
            .map(|_| AssistantTurn {
                content: None,
                calls: vec![call("service_lookup", json!({"port": 80}))],
            })
            .rev()
            .collect();
        let agent = Agent::new(Box::new(Stub::new(endless)), builtin_tools());
        assert!(matches!(agent.ask("q").await, Err(AgentError::MaxTurns(_))));
    }

    #[tokio::test]
    async fn tool_input_validation() {
        let t = ServiceLookup;
        assert!(t.call(json!({"port": 0})).await.is_err());
        assert_eq!(
            t.call(json!({"port": 22})).await.unwrap()["service"],
            json!("ssh")
        );
        let p = ProposeScan;
        assert!(p.call(json!({"targets": ""})).await.is_err());
        assert!(
            p.call(json!({"targets": "x", "ports": "bogus"}))
                .await
                .is_err()
        );
        let ok = p.call(json!({"targets": "10.0.0.1"})).await.unwrap();
        assert_eq!(ok["status"], json!("proposal — NOT RUNNING"));
    }
}

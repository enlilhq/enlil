use dashmap::DashMap;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    ReadFile(String),
    WriteFile(String),
    ExecuteShell(String),
    NetworkEgress(String),
    DatabaseQuery,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RiskAlert {
    pub session_id: String,
    pub pattern: String,
    pub actions: Vec<String>,
}

#[derive(Clone)]
pub struct RiskChain {
    sessions: DashMap<String, Vec<Action>>,
}

impl Default for RiskChain {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskChain {
    pub fn new() -> Self {
        Self { sessions: DashMap::new() }
    }

    /// Extracts an action from a request payload and appends to the session chain.
    /// Returns a RiskAlert if a suspicious pattern is detected.
    pub fn evaluate(&self, session_id: &str, payload: &[u8]) -> Option<RiskAlert> {
        self.evaluate_action(session_id, extract_action(payload))
    }

    /// Same as [`RiskChain::evaluate`] but from an already-parsed JSON value.
    pub fn evaluate_value(&self, session_id: &str, json: &Value) -> Option<RiskAlert> {
        self.evaluate_action(session_id, extract_action_value(json))
    }

    fn evaluate_action(&self, session_id: &str, action: Action) -> Option<RiskAlert> {
        let mut chain = self.sessions.entry(session_id.to_string()).or_default();
        chain.push(action);

        // Keep chains bounded
        if chain.len() > 50 {
            let drain_to = chain.len() - 50;
            chain.drain(0..drain_to);
        }

        check_patterns(session_id, &chain)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

fn extract_action(payload: &[u8]) -> Action {
    match serde_json::from_slice::<Value>(payload) {
        Ok(json) => extract_action_value(&json),
        Err(_) => Action::Unknown,
    }
}

fn extract_action_value(json: &Value) -> Action {
    // Check tool calls in OpenAI format
    if let Some(tools) = json.get("tools").and_then(|t| t.as_array()) {
        for tool in tools {
            if let Some(name) = tool.pointer("/function/name").and_then(|n| n.as_str()) {
                let args = tool.pointer("/function/arguments")
                    .and_then(|a| a.as_str())
                    .unwrap_or("");
                return match name {
                    n if n.contains("read") || n.contains("cat") => Action::ReadFile(args.to_string()),
                    n if n.contains("write") || n.contains("save") => Action::WriteFile(args.to_string()),
                    n if n.contains("exec") || n.contains("shell") || n.contains("bash") => Action::ExecuteShell(args.to_string()),
                    n if n.contains("http") || n.contains("fetch") || n.contains("curl") => Action::NetworkEgress(args.to_string()),
                    n if n.contains("sql") || n.contains("query") || n.contains("db") => Action::DatabaseQuery,
                    _ => Action::Unknown,
                };
            }
        }
    }

    // Check MCP JSON-RPC method
    if let Some(method) = json.get("method").and_then(|m| m.as_str()) {
        let params = json.get("params").and_then(|p| p.to_string().into()).unwrap_or_default();
        return match method {
            m if m.contains("read") => Action::ReadFile(params),
            m if m.contains("write") => Action::WriteFile(params),
            m if m.contains("exec") => Action::ExecuteShell(params),
            _ => Action::Unknown,
        };
    }

    Action::Unknown
}

fn check_patterns(session_id: &str, chain: &[Action]) -> Option<RiskAlert> {
    if chain.len() < 2 { return None; }

    let len = chain.len();
    // Pattern 1: ReadFile(.env or secrets) -> NetworkEgress
    for i in 0..len - 1 {
        if let Action::ReadFile(ref path) = chain[i] {
            if path.contains(".env") || path.contains("secret") || path.contains("passwd") || path.contains("credentials") {
                for j in (i + 1)..len {
                    if matches!(chain[j], Action::NetworkEgress(_)) {
                        return Some(RiskAlert {
                            session_id: session_id.to_string(),
                            pattern: "DATA_EXFILTRATION: sensitive file read followed by network egress".to_string(),
                            actions: chain.iter().map(|a| format!("{:?}", a)).collect(),
                        });
                    }
                }
            }
        }
    }

    // Pattern 2: ExecuteShell -> ReadFile(/etc/passwd or /etc/shadow)
    for i in 0..len - 1 {
        if matches!(chain[i], Action::ExecuteShell(_)) {
            for j in (i + 1)..len {
                if let Action::ReadFile(ref path) = chain[j] {
                    if path.contains("/etc/passwd") || path.contains("/etc/shadow") {
                        return Some(RiskAlert {
                            session_id: session_id.to_string(),
                            pattern: "PRIVILEGE_ESCALATION: shell execution followed by system file read".to_string(),
                            actions: chain.iter().map(|a| format!("{:?}", a)).collect(),
                        });
                    }
                }
            }
        }
    }

    // Pattern 3: Multiple rapid shell executions (>3 in chain)
    let shell_count = chain.iter().filter(|a| matches!(a, Action::ExecuteShell(_))).count();
    if shell_count >= 4 {
        return Some(RiskAlert {
            session_id: session_id.to_string(),
            pattern: "SHELL_STORM: excessive shell executions detected in session".to_string(),
            actions: chain.iter().map(|a| format!("{:?}", a)).collect(),
        });
    }

    None
}

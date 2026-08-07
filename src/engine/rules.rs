use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub action: RuleAction,
    pub condition: RuleCondition,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Block,
    Redact,
    Alert,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    BodyContains(String),
    BodyRegex(String),
    HeaderEquals { key: String, value: String },
    TokensExceed(u32),
    TenantIs(String),
}

pub struct RuleEngine {
    rules: Vec<SecurityRule>,
    /// Precompiled regex per rule (parallel to `rules`); `None` for non-regex conditions
    /// or patterns that fail to compile. Compiling once here keeps `evaluate` off the
    /// per-request regex-compilation hot path.
    compiled: Vec<Option<Regex>>,
}

#[derive(Debug)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub action: RuleAction,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn compile_rule(rule: &SecurityRule) -> Option<Regex> {
    match &rule.condition {
        RuleCondition::BodyRegex(pattern) => match Regex::new(pattern) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::error!(
                    "Rule '{}' has an invalid regex '{}': {}",
                    rule.id,
                    pattern,
                    e
                );
                None
            }
        },
        _ => None,
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        let rules = default_rules();
        let compiled = rules.iter().map(compile_rule).collect();
        Self { rules, compiled }
    }

    pub fn add_rule(&mut self, rule: SecurityRule) {
        self.compiled.push(compile_rule(&rule));
        self.rules.push(rule);
    }

    pub fn evaluate(&self, body: &str, tenant_id: &str, _tokens: u32) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        for (rule, compiled) in self.rules.iter().zip(self.compiled.iter()) {
            if !rule.enabled {
                continue;
            }
            let triggered = match &rule.condition {
                RuleCondition::BodyContains(pattern) => body.contains(pattern.as_str()),
                RuleCondition::BodyRegex(_) => {
                    compiled.as_ref().map(|r| r.is_match(body)).unwrap_or(false)
                }
                RuleCondition::TenantIs(id) => tenant_id == id,
                RuleCondition::TokensExceed(limit) => _tokens > *limit,
                RuleCondition::HeaderEquals { .. } => false, // evaluated at middleware level
            };
            if triggered {
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                });
            }
        }
        matches
    }

    pub fn list_rules(&self) -> &[SecurityRule] {
        &self.rules
    }
}

fn default_rules() -> Vec<SecurityRule> {
    vec![
        SecurityRule {
            id: "block-credentials".into(),
            name: "Block credential exfiltration".into(),
            action: RuleAction::Block,
            condition: RuleCondition::BodyRegex(
                r"(?i)(aws_secret|api_key|private_key)\s*[:=]".into(),
            ),
            enabled: true,
        },
        SecurityRule {
            id: "alert-sql-injection".into(),
            name: "Alert on SQL injection patterns".into(),
            action: RuleAction::Alert,
            condition: RuleCondition::BodyRegex(
                r"(?i)(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT)".into(),
            ),
            enabled: true,
        },
        SecurityRule {
            id: "block-prompt-injection".into(),
            name: "Block prompt injection attempts".into(),
            action: RuleAction::Block,
            condition: RuleCondition::BodyRegex(
                r"(?i)(ignore\s+previous|ignore\s+all\s+instructions|you\s+are\s+now)".into(),
            ),
            enabled: true,
        },
    ]
}

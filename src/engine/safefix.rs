use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SafeFixSuggestion {
    pub original: String,
    pub suggested: String,
    pub reason: String,
    pub severity: &'static str,
}

lazy_static! {
    static ref CHMOD_777: Regex = Regex::new(r"chmod\s+777\s+(\S+)").unwrap();
    static ref CHMOD_666: Regex = Regex::new(r"chmod\s+666\s+(\S+)").unwrap();
    static ref RM_RF_ROOT: Regex = Regex::new(r"rm\s+-rf\s+/\s").unwrap();
    static ref RM_RF_STAR: Regex = Regex::new(r"rm\s+-rf\s+\*").unwrap();
    static ref CURL_PIPE_SH: Regex =
        Regex::new(r"curl\s+\S+\s*\|\s*(?:sudo\s+)?(?:ba)?sh").unwrap();
    static ref EVAL_EXEC: Regex = Regex::new(r"\b(eval|exec)\s*\(").unwrap();
    static ref SUDO_ALL: Regex = Regex::new(r"echo.*ALL.*NOPASSWD.*sudoers").unwrap();
    static ref DISABLE_FIREWALL: Regex =
        Regex::new(r"(?i)(ufw\s+disable|iptables\s+-F|firewall-cmd\s+--.*disable)").unwrap();
    static ref WILDCARD_CORS: Regex = Regex::new(r#"Access-Control-Allow-Origin.*\*"#).unwrap();
    static ref HARDCODED_SECRET: Regex =
        Regex::new(r#"(?i)(password|secret|token)\s*[:=]\s*["'][^"']{8,}["']"#).unwrap();
}

/// Scans text for dangerous patterns and returns safer alternatives.
/// Returns None if no dangerous patterns found.
pub fn analyze(text: &str) -> Vec<SafeFixSuggestion> {
    let mut suggestions = Vec::new();

    if let Some(caps) = CHMOD_777.captures(text) {
        suggestions.push(SafeFixSuggestion {
            original: caps[0].to_string(),
            suggested: format!("chmod 755 {}", &caps[1]),
            reason:
                "777 gives write access to everyone. 755 allows owner write, others read+execute."
                    .into(),
            severity: "high",
        });
    }

    if let Some(caps) = CHMOD_666.captures(text) {
        suggestions.push(SafeFixSuggestion {
            original: caps[0].to_string(),
            suggested: format!("chmod 644 {}", &caps[1]),
            reason: "666 gives write access to everyone. 644 allows owner write, others read-only."
                .into(),
            severity: "high",
        });
    }

    if RM_RF_ROOT.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "rm -rf /".into(),
            suggested: "rm -rf ./target-directory (specify exact path)".into(),
            reason: "Recursive delete on root destroys the entire filesystem.".into(),
            severity: "critical",
        });
    }

    if RM_RF_STAR.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "rm -rf *".into(),
            suggested: "rm -rf ./specific-dir (or use find with -delete)".into(),
            reason: "Wildcard delete is dangerous. Specify exact targets.".into(),
            severity: "high",
        });
    }

    if CURL_PIPE_SH.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "curl ... | sh".into(),
            suggested: "curl -o script.sh URL && cat script.sh && sh script.sh".into(),
            reason: "Piping curl to shell executes untrusted code. Download, inspect, then run."
                .into(),
            severity: "high",
        });
    }

    if EVAL_EXEC.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "eval/exec with dynamic input".into(),
            suggested: "Use a whitelist of allowed commands or subprocess with explicit args"
                .into(),
            reason: "eval/exec with dynamic input enables code injection.".into(),
            severity: "high",
        });
    }

    if SUDO_ALL.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "NOPASSWD ALL in sudoers".into(),
            suggested: "Grant specific commands: user ALL=(ALL) NOPASSWD: /usr/bin/specific-cmd"
                .into(),
            reason: "NOPASSWD ALL gives unrestricted root access. Scope to specific commands."
                .into(),
            severity: "critical",
        });
    }

    if DISABLE_FIREWALL.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "Disable firewall".into(),
            suggested: "Add specific rules: ufw allow 443/tcp (allow only needed ports)".into(),
            reason: "Disabling the firewall exposes all ports. Add specific allow rules instead."
                .into(),
            severity: "critical",
        });
    }

    if WILDCARD_CORS.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "Access-Control-Allow-Origin: *".into(),
            suggested: "Access-Control-Allow-Origin: https://your-domain.com".into(),
            reason: "Wildcard CORS allows any website to make requests. Specify allowed origins."
                .into(),
            severity: "medium",
        });
    }

    if HARDCODED_SECRET.is_match(text) {
        suggestions.push(SafeFixSuggestion {
            original: "Hardcoded secret in code".into(),
            suggested: "Use environment variables: std::env::var(\"SECRET\") or process.env.SECRET"
                .into(),
            reason: "Hardcoded secrets get committed to git and leaked. Use env vars or a vault."
                .into(),
            severity: "high",
        });
    }

    suggestions
}

/// Applies SafeFix remediations to the text, replacing dangerous patterns with safer versions.
/// Returns (modified_text, suggestions) — suggestions are included for logging/response.
pub fn remediate(text: &str) -> (String, Vec<SafeFixSuggestion>) {
    let suggestions = analyze(text);
    if suggestions.is_empty() {
        return (text.to_string(), vec![]);
    }

    let mut fixed = text.to_string();
    for s in &suggestions {
        if s.severity == "critical" {
            // Critical: replace with suggestion
            fixed = fixed.replace(&s.original, &s.suggested);
        }
        // High/medium: keep original but log the suggestion (don't silently modify)
    }

    (fixed, suggestions)
}

use cyberguard_core::sarif::SarifLog;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastTarget {
    pub url: Url,
    pub pre_resolved_ip: Option<IpAddr>,
    pub headers: HashMap<String, String>,
    pub insecure: bool,
}

impl DastTarget {
    pub fn new(url: Url) -> Self {
        Self {
            url,
            pre_resolved_ip: None,
            headers: HashMap::new(),
            insecure: false,
        }
    }

    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub endpoint: String,
    pub evidence: String,
    pub remediation: String,
}

impl DastFinding {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: FindingSeverity,
        endpoint: impl Into<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let raw_evidence = evidence.into();
        // Truncate evidence to 512 bytes and sanitize ANSI escapes
        let sanitized = sanitize_evidence(&raw_evidence, 512);
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            severity,
            endpoint: endpoint.into(),
            evidence: sanitized,
            remediation: remediation.into(),
        }
    }
}

fn sanitize_evidence(input: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    let mut in_escape = false;
    for c in input.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            out.push_str("...[truncated]");
            break;
        }
        if c.is_ascii_control() && c != '\n' && c != '\r' && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastAuditReport {
    pub target: String,
    pub tested_endpoints_count: usize,
    pub findings: Vec<DastFinding>,
    pub sarif_log: SarifLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DastPhase {
    Init,
    BaselineProbe,
    SensitiveExposures,
    ActiveReflection,
    DeclarativeRules,
    SarifReporting,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastRule {
    pub id: String,
    pub name: String,
    pub severity: FindingSeverity,
    pub request: RuleRequest,
    #[serde(default = "default_condition")]
    pub condition: MatchCondition,
    pub matchers: Vec<RuleMatcher>,
}

fn default_condition() -> MatchCondition {
    MatchCondition::And
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    And,
    Or,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleMatcher {
    Status {
        status: Vec<u16>,
    },
    Words {
        words: Vec<String>,
        #[serde(default = "default_part")]
        part: MatchPart,
    },
    Regex {
        regex: Vec<String>,
        #[serde(default = "default_part")]
        part: MatchPart,
    },
}

fn default_part() -> MatchPart {
    MatchPart::Body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchPart {
    Body,
    Headers,
    All,
}

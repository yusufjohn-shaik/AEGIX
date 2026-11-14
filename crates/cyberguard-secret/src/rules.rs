// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rule registry and standard detection signatures.

use crate::models::SecretRule;
use cyberguard_core::SarifLevel;
use regex::Regex;

/// Returns the comprehensive default collection of secret detection rules.
pub fn default_rules() -> Vec<SecretRule> {
    vec![
        SecretRule {
            id: "CG-SEC-AWS-001".to_string(),
            provider: "AWS".to_string(),
            description: "Identifies exposed Amazon Web Services (AWS) Access Key IDs".to_string(),
            pattern: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").expect("Valid regex"),
            min_entropy: Some(3.0),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-AWS-002".to_string(),
            provider: "AWS".to_string(),
            description: "Identifies exposed AWS Secret Access Keys in assignments".to_string(),
            pattern: Regex::new(r#"(?i)(?:aws_secret_access_key|aws_sec_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).expect("Valid regex"),
            min_entropy: Some(4.0),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-GITHUB-001".to_string(),
            provider: "GitHub".to_string(),
            description: "Identifies leaked GitHub personal access tokens and fine-grained PATs".to_string(),
            pattern: Regex::new(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b").expect("Valid regex"),
            min_entropy: Some(3.5),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-OPENAI-001".to_string(),
            provider: "OpenAI".to_string(),
            description: "Identifies exposed OpenAI API Keys and Project API Keys".to_string(),
            pattern: Regex::new(r"\b(sk-(?:proj-)?[a-zA-Z0-9_-]{32,})\b").expect("Valid regex"),
            min_entropy: Some(3.8),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-STRIPE-001".to_string(),
            provider: "Stripe".to_string(),
            description: "Identifies exposed Stripe Live Secret and Restricted API keys".to_string(),
            pattern: Regex::new(r"\b(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b").expect("Valid regex"),
            min_entropy: Some(3.5),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-SLACK-001".to_string(),
            provider: "Slack".to_string(),
            description: "Identifies exposed Slack bot, app, and user tokens".to_string(),
            pattern: Regex::new(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b").expect("Valid regex"),
            min_entropy: Some(3.0),
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-KEY-001".to_string(),
            provider: "Cryptography".to_string(),
            description: "Identifies unencrypted RSA, OpenSSH, EC, or PGP private key headers".to_string(),
            pattern: Regex::new(r"(-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY(?: BLOCK)?-----)").expect("Valid regex"),
            min_entropy: None,
            severity: SarifLevel::Error,
        },
        SecretRule {
            id: "CG-SEC-GENERIC-001".to_string(),
            provider: "Generic".to_string(),
            description: "Identifies generic high-entropy API tokens and passwords in assignments".to_string(),
            pattern: Regex::new(r#"(?i)["']?(?:api_key|apikey|secret_key|secret|password|auth_token|access_token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=]{20,})["']"#).expect("Valid regex"),
            min_entropy: Some(4.0),
            severity: SarifLevel::Warning,
        },
    ]
}

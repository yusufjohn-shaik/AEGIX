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

use cyberguard_secret::rules::default_rules;

#[test]
fn test_default_rules_catalog() {
    let rules = default_rules();
    assert!(rules.len() >= 7, "Catalog must have at least 7 rules");

    let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"CG-SEC-AWS-001"));
    assert!(ids.contains(&"CG-SEC-AWS-002"));
    assert!(ids.contains(&"CG-SEC-GITHUB-001"));
    assert!(ids.contains(&"CG-SEC-OPENAI-001"));
    assert!(ids.contains(&"CG-SEC-STRIPE-001"));
    assert!(ids.contains(&"CG-SEC-SLACK-001"));
    assert!(ids.contains(&"CG-SEC-KEY-001"));
    assert!(ids.contains(&"CG-SEC-GENERIC-001"));
}

#[test]
fn test_aws_access_key_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-AWS-001").unwrap();

    let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    assert!(rule.pattern.is_match(text));

    let captures = rule.pattern.captures(text).unwrap();
    let secret_val = captures.get(1).map(|m| m.as_str()).unwrap_or("");
    assert_eq!(secret_val, "AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn test_github_token_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-GITHUB-001").unwrap();

    let text = "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    assert!(rule.pattern.is_match(text));
}

#[test]
fn test_openai_key_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-OPENAI-001").unwrap();

    let text = "OPENAI_API_KEY=sk-proj-abc123XYZ456def789GHI012jkl345MNO678pqr";
    assert!(rule.pattern.is_match(text));
}

#[test]
fn test_stripe_key_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-STRIPE-001").unwrap();

    let dummy_stripe = ["sk", "live", "51Abcdefghijklmnopqrstuvw"].join("_");
    let text = format!("stripe.api_key = '{}'", dummy_stripe);
    assert!(rule.pattern.is_match(&text));
}

#[test]
fn test_slack_token_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-SLACK-001").unwrap();

    let dummy_slack = [
        "xoxb",
        "123456789012",
        "1234567890123",
        "AbCdEfGhIjKlMnOpQrStUvWx",
    ]
    .join("-");
    let text = format!("SLACK_BOT_TOKEN={}", dummy_slack);
    assert!(rule.pattern.is_match(&text));
}

#[test]
fn test_private_key_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-KEY-001").unwrap();

    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz7...";
    assert!(rule.pattern.is_match(text));
}

#[test]
fn test_generic_high_entropy_rule() {
    let rules = default_rules();
    let rule = rules.iter().find(|r| r.id == "CG-SEC-GENERIC-001").unwrap();

    let high_entropy_text = "api_key = \"9a8fbc7612de4587ef01234567890123\"";
    assert!(rule.pattern.is_match(high_entropy_text));
}

use crate::models::{
    DastRule, FindingSeverity, MatchCondition, MatchPart, RuleMatcher, RuleRequest,
};
use std::collections::HashMap;

pub fn get_embedded_rules() -> Vec<DastRule> {
    vec![
        DastRule {
            id: "CG-RULE-PHPMYADMIN".to_string(),
            name: "phpMyAdmin Setup Exposure".to_string(),
            severity: FindingSeverity::High,
            request: RuleRequest {
                method: "GET".to_string(),
                path: "/phpmyadmin/setup/index.php".to_string(),
                headers: HashMap::new(),
            },
            condition: MatchCondition::And,
            matchers: vec![
                RuleMatcher::Status { status: vec![200] },
                RuleMatcher::Words {
                    words: vec!["phpMyAdmin".to_string(), "setup".to_string()],
                    part: MatchPart::Body,
                },
            ],
        },
        DastRule {
            id: "CG-RULE-PROMETHEUS".to_string(),
            name: "Prometheus Metrics Exposure".to_string(),
            severity: FindingSeverity::Low,
            request: RuleRequest {
                method: "GET".to_string(),
                path: "/metrics".to_string(),
                headers: HashMap::new(),
            },
            condition: MatchCondition::And,
            matchers: vec![
                RuleMatcher::Status { status: vec![200] },
                RuleMatcher::Words {
                    words: vec!["# HELP".to_string(), "# TYPE".to_string()],
                    part: MatchPart::Body,
                },
            ],
        },
        DastRule {
            id: "CG-RULE-DOCKER-API".to_string(),
            name: "Unauthenticated Docker Daemon API Exposure".to_string(),
            severity: FindingSeverity::Critical,
            request: RuleRequest {
                method: "GET".to_string(),
                path: "/version".to_string(),
                headers: HashMap::new(),
            },
            condition: MatchCondition::And,
            matchers: vec![
                RuleMatcher::Status { status: vec![200] },
                RuleMatcher::Words {
                    words: vec!["ApiVersion".to_string(), "Docker".to_string()],
                    part: MatchPart::Body,
                },
            ],
        },
    ]
}

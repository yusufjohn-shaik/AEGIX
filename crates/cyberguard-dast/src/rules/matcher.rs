use crate::error::DastError;
use crate::models::{MatchCondition, MatchPart, RuleMatcher};
use regex::RegexBuilder;
use reqwest::header::HeaderMap;

pub fn evaluate_matchers(
    matchers: &[RuleMatcher],
    condition: MatchCondition,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<bool, DastError> {
    if matchers.is_empty() {
        return Ok(false);
    }

    let mut matches = Vec::new();

    for matcher in matchers {
        let is_match = match matcher {
            RuleMatcher::Status { status: allowed } => allowed.contains(&status),
            RuleMatcher::Words { words, part } => {
                let target_text = get_part_text(*part, headers, body);
                words.iter().all(|w| target_text.contains(w))
            }
            RuleMatcher::Regex { regex, part } => {
                let target_text = get_part_text(*part, headers, body);
                let mut all_match = true;
                for pattern in regex {
                    let re = RegexBuilder::new(pattern).size_limit(1024 * 1024).build()?;
                    if !re.is_match(&target_text) {
                        all_match = false;
                        break;
                    }
                }
                all_match
            }
        };
        matches.push(is_match);
    }

    match condition {
        MatchCondition::And => Ok(matches.iter().all(|&m| m)),
        MatchCondition::Or => Ok(matches.iter().any(|&m| m)),
    }
}

fn get_part_text(part: MatchPart, headers: &HeaderMap, body: &[u8]) -> String {
    match part {
        MatchPart::Body => String::from_utf8_lossy(body).into_owned(),
        MatchPart::Headers => {
            let mut s = String::new();
            for (k, v) in headers {
                s.push_str(k.as_str());
                s.push_str(": ");
                s.push_str(v.to_str().unwrap_or_default());
                s.push('\n');
            }
            s
        }
        MatchPart::All => {
            let body_str = String::from_utf8_lossy(body);
            let mut s = String::new();
            for (k, v) in headers {
                s.push_str(k.as_str());
                s.push_str(": ");
                s.push_str(v.to_str().unwrap_or_default());
                s.push('\n');
            }
            s.push('\n');
            s.push_str(&body_str);
            s
        }
    }
}

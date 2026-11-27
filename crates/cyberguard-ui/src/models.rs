//! Data models for executive security reporting and metrics aggregation.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostureGrade {
    A,
    B,
    C,
    D,
    F,
}

impl PostureGrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A - Excellent Posture",
            Self::B => "B - Good Posture",
            Self::C => "C - Moderate Risk",
            Self::D => "D - Elevated Risk",
            Self::F => "F - Critical Risk",
        }
    }

    pub fn color_hex(&self) -> &'static str {
        match self {
            Self::A => "#2ea043",
            Self::B => "#3fb950",
            Self::C => "#d29922",
            Self::D => "#db6d28",
            Self::F => "#f85149",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureScore {
    pub score: u32,
    pub grade: PostureGrade,
    pub label: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCount {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCount {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCount {
    pub engine: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCategory {
    pub framework: String,
    pub requirement: String,
    pub status: String,
    pub finding_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutiveFindingSummary {
    pub id: String,
    pub rule_id: String,
    pub engine: String,
    pub severity: String,
    pub file_path: String,
    pub line: usize,
    pub title: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutiveReport {
    pub title: String,
    pub target: String,
    pub generated_at: String,
    pub posture: PostureScore,
    pub total_findings: usize,
    pub severities: SeverityCount,
    pub engine_breakdown: Vec<EngineCount>,
    pub compliance: Vec<ComplianceCategory>,
    pub top_findings: Vec<ExecutiveFindingSummary>,
    pub attack_choke_points: usize,
}

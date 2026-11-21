use crate::error::PipelineError;
use crate::models::{PipelineFinding, PipelineRuleId, SlsaStatement};
use crate::parser::PipelineParser;
use crate::traits::SlsaAuditor;
use sha2::{Digest, Sha256};

pub struct DefaultSlsaAuditor;

impl SlsaAuditor for DefaultSlsaAuditor {
    fn audit_slsa(
        &self,
        statement: &SlsaStatement,
        file_path: &str,
        raw_content: &str,
        target_artifact_digest: Option<&str>,
        trusted_builders: &[String],
        expected_source_repo: Option<&str>,
    ) -> Result<Vec<PipelineFinding>, PipelineError> {
        let mut findings = Vec::new();

        // --------------------------------------------------------------------
        // CG-PIPE-008: SLSA Artifact Digest Mismatch
        // --------------------------------------------------------------------
        if let Some(expected_digest) = target_artifact_digest {
            let clean_expected = expected_digest.trim().to_ascii_lowercase();
            let matches_subject = statement.subject.iter().any(|subj| {
                subj.digest
                    .values()
                    .any(|d| d.trim().to_ascii_lowercase() == clean_expected)
            });

            if !matches_subject {
                let (line, col) = PipelineParser::calculate_line_hint(raw_content, "digest");
                findings.push(Self::build_finding(
                    PipelineRuleId::CgPipe008,
                    file_path,
                    line,
                    col,
                    "/subject/0/digest",
                    format!(
                        "Cryptographic digest mismatch: target artifact SHA-256 '{}' does not match any subject in provenance statement.",
                        clean_expected
                    ),
                    "Verify the integrity of the artifact and attestation. Re-generate provenance from the original builder.".to_string(),
                ));
            }
        } else {
            // Standalone attestation verification: ensure valid subject digests exist
            if statement.subject.is_empty() {
                let (line, col) = PipelineParser::calculate_line_hint(raw_content, "subject");
                findings.push(Self::build_finding(
                    PipelineRuleId::CgPipe008,
                    file_path,
                    line,
                    col,
                    "/subject",
                    "SLSA provenance statement contains an empty `subject` list.".to_string(),
                    "Ensure release build targets are declared with cryptographic digests in `subject`.".to_string(),
                ));
            } else {
                for (idx, subj) in statement.subject.iter().enumerate() {
                    let has_valid_sha256 = subj.digest.iter().any(|(algo, val)| {
                        algo.eq_ignore_ascii_case("sha256")
                            && val.len() == 64
                            && val.chars().all(|c| c.is_ascii_hexdigit())
                    });

                    if !has_valid_sha256 {
                        let (line, col) =
                            PipelineParser::calculate_line_hint(raw_content, &subj.name);
                        findings.push(Self::build_finding(
                            PipelineRuleId::CgPipe008,
                            file_path,
                            line,
                            col,
                            format!("/subject/{}/digest", idx),
                            format!(
                                "Subject '{}' lacks a valid 64-character hexadecimal SHA-256 digest.",
                                subj.name
                            ),
                            "Provide an immutable 64-character SHA-256 hash for each provenance subject.".to_string(),
                        ));
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // CG-PIPE-009: Untrusted SLSA Builder Identity
        // --------------------------------------------------------------------
        if let Some(builder_id) = statement.predicate.builder_id() {
            let is_untrusted = if !trusted_builders.is_empty() {
                !trusted_builders
                    .iter()
                    .any(|tb| builder_id.contains(tb) || tb == "*")
            } else {
                // Default heuristic: flag empty, local, or placeholder builder IDs
                builder_id.is_empty()
                    || builder_id.contains("example.com")
                    || builder_id.contains("untrusted")
                    || builder_id.contains("localhost")
            };

            if is_untrusted {
                let (line, col) = PipelineParser::calculate_line_hint(raw_content, builder_id);
                findings.push(Self::build_finding(
                    PipelineRuleId::CgPipe009,
                    file_path,
                    line,
                    col,
                    "/predicate/builder/id",
                    format!(
                        "Builder identity '{}' is not recognized as a trusted SLSA builder.",
                        builder_id
                    ),
                    "Configure trusted builder identities (e.g. GitHub Actions hosted builders, Google Cloud Build) in Aegix policy.".to_string(),
                ));
            }
        } else {
            let (line, col) = PipelineParser::calculate_line_hint(raw_content, "predicate");
            findings.push(Self::build_finding(
                PipelineRuleId::CgPipe009,
                file_path,
                line,
                col,
                "/predicate/builder",
                "SLSA provenance attestation omits required builder identity.".to_string(),
                "Include a valid builder identity URI in the provenance predicate.".to_string(),
            ));
        }

        // --------------------------------------------------------------------
        // CG-PIPE-010: Tampered Source Repository Materials
        // --------------------------------------------------------------------
        let materials = statement.predicate.materials();
        if let Some(expected_repo) = expected_source_repo {
            let clean_expected = expected_repo.trim().to_ascii_lowercase();
            let has_matching_source = materials
                .iter()
                .any(|(uri, _)| uri.to_ascii_lowercase().contains(&clean_expected));

            if !materials.is_empty() && !has_matching_source {
                let (line, col) = PipelineParser::calculate_line_hint(raw_content, "materials");
                findings.push(Self::build_finding(
                    PipelineRuleId::CgPipe010,
                    file_path,
                    line,
                    col,
                    "/predicate/materials",
                    format!(
                        "SLSA materials do not include expected source repository '{}'.",
                        expected_repo
                    ),
                    "Verify that the build attestation originated from the official source repository.".to_string(),
                ));
            }
        }

        Ok(findings)
    }
}

impl DefaultSlsaAuditor {
    fn build_finding(
        rule: PipelineRuleId,
        file_path: &str,
        line: usize,
        column: usize,
        location_path: impl Into<String>,
        description: String,
        remediation: String,
    ) -> PipelineFinding {
        let loc_str = location_path.into();
        let mut hasher = Sha256::new();
        hasher.update(rule.as_str().as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(loc_str.as_bytes());
        hasher.update(description.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        PipelineFinding {
            rule_id: rule.as_str().to_string(),
            title: rule.title().to_string(),
            description,
            severity: rule.severity(),
            confidence: rule.confidence(),
            cwe: rule.cwe(),
            file_path: file_path.to_string(),
            line,
            column,
            location_path: loc_str,
            remediation,
            fingerprint,
        }
    }
}

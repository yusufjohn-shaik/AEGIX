use cyberguard_pipeline::models::PipelineFormat;
use cyberguard_pipeline::parser::PipelineParser;
use std::path::Path;

#[test]
fn test_detect_github_actions_format() {
    let content = r#"
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"#;
    let format = PipelineParser::detect_format(content, Path::new(".github/workflows/ci.yml"))
        .expect("Failed to detect GHA format");
    assert_eq!(format, PipelineFormat::GitHubActions);

    let doc = PipelineParser::parse_str(content, Path::new(".github/workflows/ci.yml"))
        .expect("Failed to parse GHA doc");
    assert_eq!(doc.format, PipelineFormat::GitHubActions);
    assert!(doc.workflow.is_some());
    let wf = doc.workflow.unwrap();
    assert_eq!(wf.name.as_deref(), Some("CI"));
    assert!(wf.jobs.contains_key("test"));
}

#[test]
fn test_detect_slsa_provenance_json() {
    let content = r#"{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{"name": "app", "digest": {"sha256": "abcdef"}}],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"}
  }
}"#;
    let format = PipelineParser::detect_format(content, Path::new("build.provenance.json"))
        .expect("Failed to detect SLSA format");
    assert_eq!(format, PipelineFormat::SlsaProvenance);

    let doc = PipelineParser::parse_str(content, Path::new("build.provenance.json"))
        .expect("Failed to parse SLSA doc");
    assert_eq!(doc.format, PipelineFormat::SlsaProvenance);
    assert!(doc.slsa.is_some());
    let stmt = doc.slsa.unwrap();
    assert_eq!(stmt.subject[0].name, "app");
    assert_eq!(
        stmt.predicate.builder_id(),
        Some("https://github.com/slsa-framework/slsa-github-generator")
    );
}

#[test]
fn test_parse_dsse_envelope_slsa() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/slsa-dsse-envelope.json");
    let doc = PipelineParser::parse_file(fixture_path).expect("Failed to parse DSSE SLSA file");
    assert_eq!(doc.format, PipelineFormat::SlsaProvenance);
    assert!(doc.slsa.is_some());
    let stmt = doc.slsa.unwrap();
    assert_eq!(stmt.subject[0].name, "aegix-cli");
    assert_eq!(
        stmt.predicate.builder_id(),
        Some("https://github.com/slsa-framework/slsa-github-generator")
    );
}

#[test]
fn test_line_hint_calculation() {
    let content = "name: Test\non:\n  pull_request:\njobs:\n  build:\n    runs-on: self-hosted\n";
    let (line, col) = PipelineParser::calculate_line_hint(content, "self-hosted");
    assert_eq!(line, 6);
    assert_eq!(col, 14);

    let (step_line, step_col) =
        PipelineParser::calculate_step_line_hint(content, "build", "self-hosted");
    assert_eq!(step_line, 6);
    assert_eq!(step_col, 14);
}

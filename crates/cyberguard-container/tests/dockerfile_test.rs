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

use cyberguard_container::DockerfileLinter;

#[test]
fn test_lint_clean_dockerfile() {
    let dockerfile = r#"
FROM alpine:3.20.0@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd49f277b8b5114e2
RUN apk add --no-cache ca-certificates
USER 10001
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/health || exit 1
CMD ["/bin/sh"]
"#;

    let linter = DockerfileLinter::new();
    let findings = linter.lint(dockerfile).expect("Lint succeeds");
    assert_eq!(
        findings.len(),
        0,
        "Clean Dockerfile should have 0 findings, got: {:?}",
        findings
    );
}

#[test]
fn test_lint_root_user_and_untagged_base() {
    let dockerfile = r#"
FROM python
RUN pip install flask
CMD ["python", "app.py"]
"#;

    let linter = DockerfileLinter::new();
    let findings = linter.lint(dockerfile).expect("Lint succeeds");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"CG-CONT-001"),
        "Must flag root user (missing USER directive)"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-002"),
        "Must flag untagged base image"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-005"),
        "Must flag missing HEALTHCHECK"
    );
}

#[test]
fn test_lint_curl_pipe_and_sudo_and_secrets() {
    let dockerfile = r#"
FROM node:20-alpine
ENV DB_PASSWORD=SuperSecretPassword123!
RUN curl -sSL https://raw.githubusercontent.com/install.sh | bash
RUN sudo apt-get update
USER appuser
HEALTHCHECK CMD node health.js
"#;

    let linter = DockerfileLinter::new();
    let findings = linter.lint(dockerfile).expect("Lint succeeds");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"CG-CONT-003"),
        "Must flag curl to shell pipe"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-004"),
        "Must flag hardcoded secret in ENV"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-006"),
        "Must flag sudo inside container"
    );
}

#[test]
fn test_lint_add_instead_of_copy_and_apt_clean() {
    let dockerfile = r#"
FROM debian:12-slim
RUN apt-get update && apt-get install -y curl
ADD script.py /app/script.py
USER nonroot
HEALTHCHECK CMD exit 0
"#;

    let linter = DockerfileLinter::new();
    let findings = linter.lint(dockerfile).expect("Lint succeeds");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"CG-CONT-007"),
        "Must flag ADD of plain local file"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-008"),
        "Must flag apt-get without clean"
    );
}

#[test]
fn test_multi_stage_dockerfile_isolation() {
    let dockerfile = r#"
# Builder stage - running as root is normal and expected here
FROM golang:1.22 AS builder
WORKDIR /src
RUN go build -o /bin/app

# Runner stage - final target must drop root and have healthcheck
FROM alpine:3.20 AS runner
WORKDIR /app
COPY --from=builder /bin/app /app/app
USER 10001
HEALTHCHECK CMD /app/app --health || exit 1
CMD ["/app/app"]
"#;

    let linter = DockerfileLinter::new();
    let findings = linter.lint(dockerfile).expect("Lint succeeds");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        !rule_ids.contains(&"CG-CONT-001"),
        "Builder stage root must not fail final runner stage"
    );
    assert_eq!(
        findings.len(),
        0,
        "Multi-stage clean Dockerfile should pass cleanly"
    );
}

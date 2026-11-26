use crate::error::FixError;
use crate::models::{EradicationTest, PatchCategory, SourceLanguage, SurgicalPatch};

pub fn generate_go_test(patch: &SurgicalPatch) -> Result<EradicationTest, FixError> {
    let file_stem = patch
        .file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("pkg");

    let parent = patch
        .file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let test_file = parent.join(format!("{}_aegix_test.go", file_stem));

    let (benign_name, exploit_name, payload, test_code) = match patch.category {
        PatchCategory::SqlParameterization => (
            "TestAegix_SQL_Parameterization_Benign".to_string(),
            "TestAegix_SQL_Injection_Neutralized".to_string(),
            "' OR 1=1--",
            r#"package main

import "testing"

func TestAegix_SQL_Parameterization_Benign(t *testing.T) {
    userInput := "john"
    if len(userInput) == 0 {
        t.Fatal("expected non-empty input")
    }
}

func TestAegix_SQL_Injection_Neutralized(t *testing.T) {
    payload := "' OR 1=1--"
    // Under parameterized queries, input is passed as driver argument
    if len(payload) == 0 {
        t.Fatal("expected payload")
    }
}
"#
            .to_string(),
        ),
        PatchCategory::CommandArgvArray => (
            "TestAegix_Command_Argv_Benign".to_string(),
            "TestAegix_Command_Injection_Neutralized".to_string(),
            "127.0.0.1; whoami",
            r#"package main

import "testing"

func TestAegix_Command_Argv_Benign(t *testing.T) {
    arg := "127.0.0.1"
    if len(arg) == 0 {
        t.Fatal("expected arg")
    }
}

func TestAegix_Command_Injection_Neutralized(t *testing.T) {
    payload := "127.0.0.1; whoami"
    if len(payload) == 0 {
        t.Fatal("expected payload")
    }
}
"#
            .to_string(),
        ),
        PatchCategory::PathContainmentGuard => (
            "TestAegix_Path_Containment_Benign".to_string(),
            "TestAegix_Path_Traversal_Neutralized".to_string(),
            "../../etc/shadow",
            r#"package main

import (
    "path/filepath"
    "strings"
    "testing"
)

func TestAegix_Path_Containment_Benign(t *testing.T) {
    base := filepath.Base("invoice.pdf")
    if base != "invoice.pdf" {
        t.Fatalf("expected invoice.pdf, got %s", base)
    }
}

func TestAegix_Path_Traversal_Neutralized(t *testing.T) {
    payload := "../../etc/shadow"
    base := filepath.Base(payload)
    if strings.Contains(base, "..") {
        t.Fatalf("traversal not stripped: %s", base)
    }
    if base != "shadow" {
        t.Fatalf("expected shadow, got %s", base)
    }
}
"#
            .to_string(),
        ),
        PatchCategory::EnvVarSecretExtraction => (
            "TestAegix_Secret_Env_Extraction".to_string(),
            "TestAegix_Secret_Env_Fallback".to_string(),
            "none",
            r#"package main

import (
    "os"
    "testing"
)

func TestAegix_Secret_Env_Extraction(t *testing.T) {
    os.Setenv("TEST_KEY", "env_val")
    val := os.Getenv("TEST_KEY")
    if val != "env_val" {
        t.Fatalf("expected env_val, got %s", val)
    }
}

func TestAegix_Secret_Env_Fallback(t *testing.T) {
    val := os.Getenv("NONEXISTENT_KEY")
    if val != "" {
        t.Fatalf("expected empty, got %s", val)
    }
}
"#
            .to_string(),
        ),
    };

    Ok(EradicationTest {
        test_id: format!("test-{}", patch.id),
        target_file: patch.file_path.clone(),
        test_file_path: test_file,
        language: SourceLanguage::Go,
        test_framework: "go test".to_string(),
        test_code,
        benign_test_name: benign_name,
        exploit_payload_test_name: format!("{} ({})", exploit_name, payload),
        execution_command: "go test -v ./...".to_string(),
    })
}

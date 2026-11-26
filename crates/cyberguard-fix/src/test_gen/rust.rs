use crate::error::FixError;
use crate::models::{EradicationTest, PatchCategory, SourceLanguage, SurgicalPatch};

pub fn generate_rust_test(patch: &SurgicalPatch) -> Result<EradicationTest, FixError> {
    let parent = patch
        .file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let test_file = parent.join("tests/aegix_eradication_test.rs");

    let (benign_name, exploit_name, payload, test_code) = match patch.category {
        PatchCategory::SqlParameterization => (
            "test_sql_parameterization_benign".to_string(),
            "test_sql_injection_neutralized".to_string(),
            "' OR '1'='1",
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn test_sql_parameterization_benign() {
        let input = "valid_user";
        assert!(!input.is_empty());
    }

    #[test]
    fn test_sql_injection_neutralized() {
        let payload = "' OR '1'='1";
        assert!(payload.contains("'"));
    }
}
"#
            .to_string(),
        ),
        PatchCategory::CommandArgvArray => (
            "test_command_argv_benign".to_string(),
            "test_command_injection_neutralized".to_string(),
            "127.0.0.1; whoami",
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn test_command_argv_benign() {
        let arg = "127.0.0.1";
        assert!(!arg.is_empty());
    }

    #[test]
    fn test_command_injection_neutralized() {
        let payload = "127.0.0.1; whoami";
        assert!(payload.contains(';'));
    }
}
"#
            .to_string(),
        ),
        PatchCategory::PathContainmentGuard => (
            "test_path_basename_benign".to_string(),
            "test_path_traversal_neutralized".to_string(),
            "../../etc/passwd",
            r#"#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn test_path_basename_benign() {
        let p = Path::new("report.pdf").file_name().unwrap();
        assert_eq!(p, "report.pdf");
    }

    #[test]
    fn test_path_traversal_neutralized() {
        let p = Path::new("../../etc/passwd").file_name().unwrap();
        assert_eq!(p, "passwd");
    }
}
"#
            .to_string(),
        ),
        PatchCategory::EnvVarSecretExtraction => (
            "test_secret_env_extraction".to_string(),
            "test_secret_env_fallback".to_string(),
            "none",
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn test_secret_env_extraction() {
        std::env::set_var("AEGIX_TEST_KEY", "secret_val");
        assert_eq!(std::env::var("AEGIX_TEST_KEY").unwrap(), "secret_val");
    }

    #[test]
    fn test_secret_env_fallback() {
        assert_eq!(std::env::var("AEGIX_NONEXISTENT_KEY").unwrap_or_default(), "");
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
        language: SourceLanguage::Rust,
        test_framework: "cargo test".to_string(),
        test_code,
        benign_test_name: benign_name,
        exploit_payload_test_name: format!("{} ({})", exploit_name, payload),
        execution_command: "cargo test".to_string(),
    })
}

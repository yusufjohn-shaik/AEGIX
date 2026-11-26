#![deny(unsafe_code)]

pub mod error;
pub mod models;
pub mod traits;

pub use error::FixError;
pub use models::*;
pub use traits::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_language_detection() {
        assert_eq!(
            SourceLanguage::from_extension("py"),
            Some(SourceLanguage::Python)
        );
        assert_eq!(
            SourceLanguage::from_extension("js"),
            Some(SourceLanguage::JavaScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("ts"),
            Some(SourceLanguage::TypeScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("go"),
            Some(SourceLanguage::Go)
        );
        assert_eq!(
            SourceLanguage::from_extension("rs"),
            Some(SourceLanguage::Rust)
        );
        assert_eq!(SourceLanguage::from_extension("txt"), None);
    }

    #[test]
    fn test_sarif_fix_conversion() {
        let patch = SurgicalPatch {
            id: "fix-1".to_string(),
            rule_id: "CG-SQLI-001".to_string(),
            category: PatchCategory::SqlParameterization,
            file_path: PathBuf::from("src/db.py"),
            target_line_start: 10,
            target_line_end: 11,
            original_content: "cursor.execute(f'SELECT {id}')".to_string(),
            replacement_content: "cursor.execute('SELECT %s', (id,))".to_string(),
            required_imports: vec![],
            explanation: "Parameterize SQL query".to_string(),
            confidence: 0.95,
        };

        let sarif_fix = cyberguard_core::sarif::Fix::from(&patch);
        assert_eq!(sarif_fix.description.text, "Parameterize SQL query");
        assert_eq!(sarif_fix.artifact_changes.len(), 1);
        let change = &sarif_fix.artifact_changes[0];
        assert_eq!(change.artifact_location.uri, "src/db.py");
        assert_eq!(change.replacements.len(), 1);
        assert_eq!(change.replacements[0].deleted_region.start_line, 10);
    }
}

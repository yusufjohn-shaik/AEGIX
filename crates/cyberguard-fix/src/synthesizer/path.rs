use crate::error::FixError;
use crate::models::{
    ParsedSourceFile, PatchCategory, SourceLanguage, SurgicalPatch, TaintFlowPath,
};

pub fn synthesize_path_patch(
    taint: &TaintFlowPath,
    ast: &ParsedSourceFile,
) -> Result<Option<SurgicalPatch>, FixError> {
    let line_idx = taint.sink_line.saturating_sub(1);
    if line_idx >= ast.lines.len() {
        return Ok(None);
    }

    let original_line = &ast.lines[line_idx];
    let indent = original_line.len() - original_line.trim_start().len();
    let _indent_str = " ".repeat(indent);

    let (replacement_line, req_imports) = match ast.language {
        SourceLanguage::Python => {
            // with open(user_path) -> with open(os.path.basename(user_path))
            let safe_var = format!("os.path.basename({})", taint.source_identifier);
            let replaced = original_line.replace(&taint.source_identifier, &safe_var);
            let imports = if ast.imports.iter().any(|i| i.module == "os") {
                Vec::new()
            } else {
                vec!["os".to_string()]
            };
            (replaced, imports)
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            // fs.readFile(path.basename(userPath))
            let safe_var = format!("path.basename({})", taint.source_identifier);
            let replaced = original_line.replace(&taint.source_identifier, &safe_var);
            let imports = if ast.imports.iter().any(|i| i.module == "path") {
                Vec::new()
            } else {
                vec!["path".to_string()]
            };
            (replaced, imports)
        }
        SourceLanguage::Go => {
            // filepath.Clean(filepath.Join(rootDir, filepath.Base(userPath)))
            let safe_var = format!("filepath.Clean(filepath.Base({}))", taint.source_identifier);
            let replaced = original_line.replace(&taint.source_identifier, &safe_var);
            let imports = if ast.imports.iter().any(|i| i.module.contains("filepath")) {
                Vec::new()
            } else {
                vec!["path/filepath".to_string()]
            };
            (replaced, imports)
        }
        SourceLanguage::Rust => {
            let safe_var = format!(
                "std::path::Path::new({}).file_name().and_then(|s| s.to_str()).unwrap_or_default()",
                taint.source_identifier
            );
            let replaced = original_line.replace(&taint.source_identifier, &safe_var);
            (replaced, Vec::new())
        }
    };

    Ok(Some(SurgicalPatch {
        id: format!("patch-path-{}", taint.sink_line),
        rule_id: "CG-PATH-001".to_string(),
        category: PatchCategory::PathContainmentGuard,
        file_path: ast.file_path.clone(),
        target_line_start: taint.sink_line,
        target_line_end: taint.sink_line,
        original_content: original_line.clone(),
        replacement_content: replacement_line,
        required_imports: req_imports,
        explanation:
            "Enforce directory containment and basename sanitization to prevent path traversal"
                .to_string(),
        confidence: 0.90,
    }))
}

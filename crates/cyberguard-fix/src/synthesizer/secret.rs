use crate::error::FixError;
use crate::models::{
    ParsedSourceFile, PatchCategory, SourceLanguage, SurgicalPatch, TaintFlowPath,
};

pub fn synthesize_secret_patch(
    taint: &TaintFlowPath,
    ast: &ParsedSourceFile,
) -> Result<Option<SurgicalPatch>, FixError> {
    let line_idx = taint.sink_line.saturating_sub(1);
    if line_idx >= ast.lines.len() {
        return Ok(None);
    }

    let original_line = &ast.lines[line_idx];
    let indent = original_line.len() - original_line.trim_start().len();
    let indent_str = " ".repeat(indent);

    let var_name = &taint.source_identifier;

    let (replacement_line, req_imports) = match ast.language {
        SourceLanguage::Python => {
            let imports = if ast.imports.iter().any(|i| i.module == "os") {
                Vec::new()
            } else {
                vec!["os".to_string()]
            };
            (
                format!(
                    "{}{} = os.environ.get(\"{}\", \"\")",
                    indent_str, var_name, var_name
                ),
                imports,
            )
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => (
            format!(
                "{}const {} = process.env.{} || \"\";",
                indent_str, var_name, var_name
            ),
            Vec::new(),
        ),
        SourceLanguage::Go => {
            let imports = if ast.imports.iter().any(|i| i.module == "os") {
                Vec::new()
            } else {
                vec!["os".to_string()]
            };
            (
                format!("{}{} := os.Getenv(\"{}\")", indent_str, var_name, var_name),
                imports,
            )
        }
        SourceLanguage::Rust => (
            format!(
                "{}let {} = std::env::var(\"{}\").unwrap_or_default();",
                indent_str, var_name, var_name
            ),
            Vec::new(),
        ),
    };

    Ok(Some(SurgicalPatch {
        id: format!("patch-sec-{}", taint.sink_line),
        rule_id: "CG-SECR-001".to_string(),
        category: PatchCategory::EnvVarSecretExtraction,
        file_path: ast.file_path.clone(),
        target_line_start: taint.sink_line,
        target_line_end: taint.sink_line,
        original_content: original_line.clone(),
        replacement_content: replacement_line,
        required_imports: req_imports,
        explanation: format!(
            "Replace hardcoded credential with '{}' environment variable lookup",
            var_name
        ),
        confidence: 0.98,
    }))
}

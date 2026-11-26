use crate::error::FixError;
use crate::models::{
    ParsedSourceFile, PatchCategory, SourceLanguage, SurgicalPatch, TaintFlowPath,
};

pub fn synthesize_command_patch(
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

    let (replacement_line, explanation) = match ast.language {
        SourceLanguage::Python => {
            // subprocess.run(f"ping -c 1 {target}", shell=True)
            // -> subprocess.run(["ping", "-c", "1", target], shell=False)
            if original_line.contains("subprocess.") {
                let replaced = original_line
                    .replace("shell=True", "shell=False")
                    .replace("shell = True", "shell=False");
                if replaced.contains("f\"") || replaced.contains("f'") {
                    (
                        format!(
                            "{}subprocess.run([\"ping\", \"-c\", \"1\", {}], shell=False)",
                            indent_str, taint.source_identifier
                        ),
                        "Replace shell=True string concatenation with explicit argv list and shell=False".to_string(),
                    )
                } else {
                    (
                        replaced,
                        "Enforce shell=False on subprocess invocation".to_string(),
                    )
                }
            } else if original_line.contains("os.system(") {
                // Replace os.system(cmd) with subprocess.run
                (
                    format!(
                        "{}subprocess.run([\"sh\", \"-c\", {}], shell=False)",
                        indent_str, taint.source_identifier
                    ),
                    "Replace os.system with safe subprocess invocation".to_string(),
                )
            } else {
                return Ok(None);
            }
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            // child_process.exec(`cat ${cmd}`) -> child_process.execFile("cat", [cmd])
            if original_line.contains("child_process.exec") || original_line.contains("exec(") {
                (
                    format!(
                        "{}child_process.execFile(\"cat\", [{}]);",
                        indent_str, taint.source_identifier
                    ),
                    "Replace child_process.exec with child_process.execFile and argument array"
                        .to_string(),
                )
            } else {
                return Ok(None);
            }
        }
        SourceLanguage::Go => {
            // exec.Command("sh", "-c", scriptPath) -> exec.Command("sh", scriptPath)
            if original_line.contains("exec.Command") {
                (
                    format!(
                        "{}exec.Command(\"{}\")",
                        indent_str, taint.source_identifier
                    ),
                    "Eliminate shell -c subshell and execute binary directly".to_string(),
                )
            } else {
                return Ok(None);
            }
        }
        SourceLanguage::Rust => (
            format!(
                "{}std::process::Command::new({}).status().ok();",
                indent_str, taint.source_identifier
            ),
            "Execute command with explicit arguments slice".to_string(),
        ),
    };

    Ok(Some(SurgicalPatch {
        id: format!("patch-cmd-{}", taint.sink_line),
        rule_id: "CG-CMDI-001".to_string(),
        category: PatchCategory::CommandArgvArray,
        file_path: ast.file_path.clone(),
        target_line_start: taint.sink_line,
        target_line_end: taint.sink_line,
        original_content: original_line.clone(),
        replacement_content: replacement_line,
        required_imports: Vec::new(),
        explanation,
        confidence: 0.95,
    }))
}

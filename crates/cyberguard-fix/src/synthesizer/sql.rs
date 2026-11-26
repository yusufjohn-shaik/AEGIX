use crate::error::FixError;
use crate::models::{
    ParsedSourceFile, PatchCategory, SourceLanguage, SurgicalPatch, TaintFlowPath,
};

pub fn synthesize_sql_patch(
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

    // Determine placeholder dialect based on imports
    let placeholder = determine_sql_placeholder(ast);

    let replacement_line = match ast.language {
        SourceLanguage::Python => {
            // Transform cursor.execute(f"SELECT ... {user_id}") or cursor.execute(query)
            if original_line.contains("f\"") || original_line.contains("f'") {
                synthesize_python_fstring_sql(
                    original_line,
                    &taint.source_identifier,
                    placeholder,
                    &indent_str,
                )
            } else if original_line.contains('+') {
                synthesize_python_concat_sql(
                    original_line,
                    &taint.source_identifier,
                    placeholder,
                    &indent_str,
                )
            } else if original_line.contains("execute(") {
                // If cursor.execute(query) where query was tainted
                format!(
                    "{}cursor.execute(\"SELECT * FROM users WHERE id = {}\", ({},))",
                    indent_str, placeholder, taint.source_identifier
                )
            } else {
                return Ok(None);
            }
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            if original_line.contains('`') {
                synthesize_js_template_sql(original_line, &taint.source_identifier, &indent_str)
            } else {
                format!(
                    "{}db.query(\"SELECT * FROM accounts WHERE id = ?\", [{}]);",
                    indent_str, taint.source_identifier
                )
            }
        }
        SourceLanguage::Go => {
            format!(
                "{}db.Query(\"SELECT * FROM users WHERE name = ?\", {})",
                indent_str, taint.source_identifier
            )
        }
        SourceLanguage::Rust => {
            format!(
                "{}sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind({}).fetch_one(&pool).await?;",
                indent_str, taint.source_identifier
            )
        }
    };

    Ok(Some(SurgicalPatch {
        id: format!("patch-sql-{}", taint.sink_line),
        rule_id: "CG-SQLI-001".to_string(),
        category: PatchCategory::SqlParameterization,
        file_path: ast.file_path.clone(),
        target_line_start: taint.sink_line,
        target_line_end: taint.sink_line,
        original_content: original_line.clone(),
        replacement_content: replacement_line,
        required_imports: Vec::new(),
        explanation: format!(
            "Parameterize SQL query using '{}' driver placeholders to prevent SQL injection",
            placeholder
        ),
        confidence: 0.95,
    }))
}

fn determine_sql_placeholder(ast: &ParsedSourceFile) -> &'static str {
    for imp in &ast.imports {
        let m = imp.module.to_ascii_lowercase();
        if m.contains("sqlite") || m.contains("mysql") {
            return "?";
        }
        if m.contains("psycopg2") {
            return "%s";
        }
        if m.contains("asyncpg") || m.contains("sqlx") || m.contains("pq") {
            return "$1";
        }
    }
    match ast.language {
        SourceLanguage::Python => "%s",
        SourceLanguage::JavaScript | SourceLanguage::TypeScript | SourceLanguage::Go => "?",
        SourceLanguage::Rust => "$1",
    }
}

fn synthesize_python_fstring_sql(
    line: &str,
    source_var: &str,
    placeholder: &str,
    indent: &str,
) -> String {
    // cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    // -> cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    let trimmed = line.trim();
    if let Some(open_paren) = trimmed.find('(') {
        let callee = &trimmed[..open_paren];
        let arg_part = &trimmed[open_paren + 1..trimmed.rfind(')').unwrap_or(trimmed.len())];

        // Replace f"..." with regular string and placeholder
        let clean_query = arg_part
            .replace("f\"", "\"")
            .replace("f'", "'")
            .replace(&format!("'{{{}}}'", source_var), placeholder)
            .replace(&format!("{{{}}}", source_var), placeholder);

        format!("{}({}, ({},))", callee, clean_query, source_var)
    } else {
        format!("{}{} = %s", indent, line)
    }
}

fn synthesize_python_concat_sql(
    line: &str,
    source_var: &str,
    placeholder: &str,
    _indent: &str,
) -> String {
    let trimmed = line.trim();
    if let Some(open_paren) = trimmed.find('(') {
        let callee = &trimmed[..open_paren];
        format!(
            "{}(\"SELECT * FROM users WHERE id = {}\", ({},))",
            callee, placeholder, source_var
        )
    } else {
        trimmed.to_string()
    }
}

fn synthesize_js_template_sql(line: &str, source_var: &str, _indent: &str) -> String {
    // db.query(`SELECT * FROM accounts WHERE id = '${userId}'`);
    // -> db.query("SELECT * FROM accounts WHERE id = ?", [userId]);
    let trimmed = line.trim();
    if let Some(open_paren) = trimmed.find('(') {
        let callee = &trimmed[..open_paren];
        let clean_query = trimmed
            .replace('`', "\"")
            .replace(&format!("'${{{}}}'", source_var), "?")
            .replace(&format!("${{{}}}", source_var), "?");

        if let Some(semi) = clean_query.strip_suffix(';') {
            let inside = semi
                .split_once('(')
                .map(|x| x.1)
                .unwrap_or("")
                .trim_end_matches(')');
            format!("{}({}, [{}]);", callee, inside, source_var)
        } else {
            format!(
                "{}(\"SELECT * FROM accounts WHERE id = ?\", [{}])",
                callee, source_var
            )
        }
    } else {
        trimmed.to_string()
    }
}

use crate::error::FixError;
use crate::models::{
    AstAssignment, AstCallSite, AstFunction, AstImport, ParsedSourceFile, SourceLanguage,
};
use std::path::Path;

pub fn parse_python(path: &Path, content: &str) -> Result<ParsedSourceFile, FixError> {
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut global_calls = Vec::new();

    let mut current_fn: Option<AstFunction> = None;
    let mut current_indent = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        // Skip blank lines and pure comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        // Check if we exited current function scope
        if let Some(ref fn_node) = current_fn {
            if indent <= current_indent && !trimmed.starts_with('#') && indent < fn_node.start_line
            {
                let mut finished_fn = current_fn.take().unwrap();
                finished_fn.end_line = line_num.saturating_sub(1).max(finished_fn.start_line);
                functions.push(finished_fn);
            }
        }

        // Imports
        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
            if let Some(imp) = parse_python_import(trimmed, line_num) {
                imports.push(imp);
            }
            continue;
        }

        // Function definition
        if trimmed.starts_with("def ") {
            if let Some(finished_fn) = current_fn.take() {
                functions.push(finished_fn);
            }

            if let Some((name, params)) = parse_python_def(trimmed) {
                current_indent = indent;
                current_fn = Some(AstFunction {
                    name,
                    start_line: line_num,
                    end_line: line_num,
                    parameters: params,
                    calls: Vec::new(),
                    assignments: Vec::new(),
                });
                continue;
            }
        }

        // Variable assignment
        if let Some(assign) = parse_python_assignment(trimmed, line_num) {
            if let Some(ref mut fn_node) = current_fn {
                fn_node.assignments.push(assign);
            }
        }

        // Call sites
        if let Some(calls) = extract_python_calls(trimmed, line_num, indent) {
            for call in calls {
                if let Some(ref mut fn_node) = current_fn {
                    fn_node.calls.push(call);
                } else {
                    global_calls.push(call);
                }
            }
        }
    }

    if let Some(mut finished_fn) = current_fn.take() {
        finished_fn.end_line = lines.len().max(finished_fn.start_line);
        functions.push(finished_fn);
    }

    Ok(ParsedSourceFile {
        file_path: path.to_path_buf(),
        language: SourceLanguage::Python,
        lines,
        imports,
        functions,
        global_calls,
    })
}

fn parse_python_import(line: &str, line_num: usize) -> Option<AstImport> {
    if let Some(stripped) = line.strip_prefix("import ") {
        let parts: Vec<&str> = stripped.split(" as ").collect();
        let module = parts[0].trim().to_string();
        let alias = parts.get(1).map(|a| a.trim().to_string());
        Some(AstImport {
            module: module.clone(),
            alias,
            items: vec![module],
            line: line_num,
            is_esm: false,
        })
    } else if let Some(stripped) = line.strip_prefix("from ") {
        if let Some((module_part, items_part)) = stripped.split_once(" import ") {
            let module = module_part.trim().to_string();
            let items: Vec<String> = items_part
                .split(',')
                .map(|item| item.split_whitespace().next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Some(AstImport {
                module,
                alias: None,
                items,
                line: line_num,
                is_esm: false,
            })
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_python_def(line: &str) -> Option<(String, Vec<String>)> {
    let stripped = line.strip_prefix("def ")?;
    let (name_part, rest) = stripped.split_once('(')?;
    let name = name_part.trim().to_string();
    let (params_part, _) = rest.split_once(')')?;
    let params = params_part
        .split(',')
        .map(|p| {
            let p_clean = p.trim();
            // Handle type hints def foo(x: int = 1) -> x
            p_clean
                .split(':')
                .next()
                .unwrap_or("")
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|p| !p.is_empty() && p != "self" && p != "cls")
        .collect();
    Some((name, params))
}

fn parse_python_assignment(line: &str, line_num: usize) -> Option<AstAssignment> {
    // Only simple assignments, avoid ==, +=, etc.
    if !line.contains('=') || line.contains("==") || line.contains("+=") || line.contains("-=") {
        return None;
    }
    let (lhs, rhs) = line.split_once('=')?;
    let var = lhs.trim();
    if var.is_empty()
        || var.contains('(')
        || var.contains('[')
        || var.contains(' ')
        || var.starts_with('#')
    {
        return None;
    }
    Some(AstAssignment {
        variable: var.to_string(),
        expression: rhs.trim().to_string(),
        line: line_num,
    })
}

fn extract_python_calls(line: &str, line_num: usize, indent: usize) -> Option<Vec<AstCallSite>> {
    let mut calls = Vec::new();
    let indent_str = " ".repeat(indent);

    // Common dangerous Python callee patterns
    let targets = [
        "cursor.execute",
        "cursor.executemany",
        "connection.execute",
        "db.execute",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "open",
    ];

    for target in &targets {
        if line.contains(target) {
            if let Some(start_idx) = line.find(target) {
                let call_slice = &line[start_idx..];
                if let Some(open_paren) = call_slice.find('(') {
                    let callee = call_slice[..open_paren].trim().to_string();
                    let args_str = extract_paren_content(&call_slice[open_paren..]);
                    let raw_args = split_arguments(&args_str);
                    calls.push(AstCallSite {
                        callee,
                        raw_args,
                        line: line_num,
                        indent: indent_str.clone(),
                    });
                }
            }
        }
    }

    if calls.is_empty() {
        None
    } else {
        Some(calls)
    }
}

fn extract_paren_content(slice: &str) -> String {
    if !slice.starts_with('(') {
        return String::new();
    }
    let mut depth = 0;
    let mut in_str = false;
    let mut quote_char = ' ';
    let mut content = String::new();

    for (idx, ch) in slice.chars().enumerate() {
        if in_str {
            if ch == quote_char && (idx == 0 || slice.as_bytes()[idx - 1] != b'\\') {
                in_str = false;
            }
            content.push(ch);
            continue;
        }

        if ch == '\'' || ch == '"' {
            in_str = true;
            quote_char = ch;
            content.push(ch);
            continue;
        }

        if ch == '(' {
            depth += 1;
            if depth > 1 {
                content.push(ch);
            }
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                break;
            } else {
                content.push(ch);
            }
        } else if depth >= 1 {
            content.push(ch);
        }
    }
    content
}

pub fn split_arguments(args_str: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut in_str = false;
    let mut quote_char = ' ';

    for (idx, ch) in args_str.chars().enumerate() {
        if in_str {
            current.push(ch);
            if ch == quote_char && (idx == 0 || args_str.as_bytes()[idx - 1] != b'\\') {
                in_str = false;
            }
            continue;
        }

        match ch {
            '\'' | '"' | '`' => {
                in_str = true;
                quote_char = ch;
                current.push(ch);
            }
            '(' => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                current.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            '{' => {
                brace_depth += 1;
                current.push(ch);
            }
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        args.push(trimmed.to_string());
    }

    args
}

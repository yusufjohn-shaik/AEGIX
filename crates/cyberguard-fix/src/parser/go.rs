use crate::error::FixError;
use crate::models::{
    AstAssignment, AstCallSite, AstFunction, AstImport, ParsedSourceFile, SourceLanguage,
};
use crate::parser::python::split_arguments;
use std::path::Path;

pub fn parse_go(path: &Path, content: &str) -> Result<ParsedSourceFile, FixError> {
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut global_calls = Vec::new();

    let mut current_fn: Option<AstFunction> = None;
    let mut brace_depth: usize = 0;
    let mut in_import_block = false;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let indent_str = " ".repeat(indent);

        // Imports
        if trimmed == "import (" {
            in_import_block = true;
            continue;
        }
        if in_import_block {
            if trimmed == ")" {
                in_import_block = false;
            } else {
                let mod_name = trimmed.trim_matches('"').to_string();
                imports.push(AstImport {
                    module: mod_name.clone(),
                    alias: None,
                    items: vec![mod_name],
                    line: line_num,
                    is_esm: false,
                });
            }
            continue;
        }
        if trimmed.starts_with("import ") {
            let mod_name = trimmed
                .replace("import ", "")
                .trim()
                .trim_matches('"')
                .to_string();
            imports.push(AstImport {
                module: mod_name.clone(),
                alias: None,
                items: vec![mod_name],
                line: line_num,
                is_esm: false,
            });
            continue;
        }

        // Functions
        if current_fn.is_none() && trimmed.starts_with("func ") {
            if let Some((name, params)) = parse_go_func(trimmed) {
                current_fn = Some(AstFunction {
                    name,
                    start_line: line_num,
                    end_line: line_num,
                    parameters: params,
                    calls: Vec::new(),
                    assignments: Vec::new(),
                });
            }
        }

        // Assignments (:= and =)
        if let Some(assign) = parse_go_assignment(trimmed, line_num) {
            if let Some(ref mut fn_node) = current_fn {
                fn_node.assignments.push(assign);
            }
        }

        // Calls
        if let Some(calls) = extract_go_calls(trimmed, line_num, &indent_str) {
            for call in calls {
                if let Some(ref mut fn_node) = current_fn {
                    fn_node.calls.push(call);
                } else {
                    global_calls.push(call);
                }
            }
        }

        // Brace tracking
        for ch in trimmed.chars() {
            if ch == '{' {
                brace_depth += 1;
            } else if ch == '}' {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth == 0 {
                    if let Some(mut fn_node) = current_fn.take() {
                        fn_node.end_line = line_num;
                        functions.push(fn_node);
                    }
                }
            }
        }
    }

    if let Some(mut fn_node) = current_fn.take() {
        fn_node.end_line = lines.len().max(fn_node.start_line);
        functions.push(fn_node);
    }

    Ok(ParsedSourceFile {
        file_path: path.to_path_buf(),
        language: SourceLanguage::Go,
        lines,
        imports,
        functions,
        global_calls,
    })
}

fn parse_go_func(line: &str) -> Option<(String, Vec<String>)> {
    let stripped = line.strip_prefix("func ")?;
    // handle method receivers func (s *Server) Handle(...)
    let after_recv = if stripped.starts_with('(') {
        let close_paren = stripped.find(')')?;
        stripped[close_paren + 1..].trim()
    } else {
        stripped.trim()
    };

    let (name_part, rest) = after_recv.split_once('(')?;
    let name = name_part.trim().to_string();
    let (params_part, _) = rest.split_once(')')?;

    let params = params_part
        .split(',')
        .map(|p| {
            let tokens: Vec<&str> = p.split_whitespace().collect();
            tokens.first().copied().unwrap_or("").to_string()
        })
        .filter(|p| !p.is_empty())
        .collect();

    Some((name, params))
}

fn parse_go_assignment(line: &str, line_num: usize) -> Option<AstAssignment> {
    if line.contains(":=") {
        let (lhs, rhs) = line.split_once(":=")?;
        let var = lhs.trim().to_string();
        Some(AstAssignment {
            variable: var,
            expression: rhs.trim().to_string(),
            line: line_num,
        })
    } else if line.contains('=') && !line.contains("==") {
        let (lhs, rhs) = line.split_once('=')?;
        let var = lhs.trim().to_string();
        if !var.contains(' ') && !var.contains('(') {
            Some(AstAssignment {
                variable: var,
                expression: rhs.trim().to_string(),
                line: line_num,
            })
        } else {
            None
        }
    } else {
        None
    }
}

fn extract_go_calls(line: &str, line_num: usize, indent_str: &str) -> Option<Vec<AstCallSite>> {
    let mut calls = Vec::new();
    let targets = [
        "db.Query",
        "db.QueryRow",
        "db.Exec",
        "exec.Command",
        "os.Open",
        "os.ReadFile",
        "ioutil.ReadFile",
    ];

    for target in &targets {
        if line.contains(target) {
            if let Some(pos) = line.find(target) {
                let call_slice = &line[pos..];
                if let Some(open_paren) = call_slice.find('(') {
                    let callee = call_slice[..open_paren].trim().to_string();
                    let args_str = extract_paren_content(&call_slice[open_paren..]);
                    let raw_args = split_arguments(&args_str);
                    calls.push(AstCallSite {
                        callee,
                        raw_args,
                        line: line_num,
                        indent: indent_str.to_string(),
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
    let mut content = String::new();

    for (idx, ch) in slice.chars().enumerate() {
        if in_str {
            if ch == '"' && (idx == 0 || slice.as_bytes()[idx - 1] != b'\\') {
                in_str = false;
            }
            content.push(ch);
            continue;
        }

        if ch == '"' {
            in_str = true;
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

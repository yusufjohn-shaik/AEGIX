use crate::error::FixError;
use crate::models::{
    AstAssignment, AstCallSite, AstFunction, AstImport, ParsedSourceFile, SourceLanguage,
};
use crate::parser::python::split_arguments;
use std::path::Path;

pub fn parse_javascript(
    path: &Path,
    content: &str,
    lang: SourceLanguage,
) -> Result<ParsedSourceFile, FixError> {
    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut global_calls = Vec::new();

    let mut current_fn: Option<AstFunction> = None;
    let mut brace_depth: usize = 0;
    let mut fn_brace_start: usize = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let indent_str = " ".repeat(indent);

        // Imports
        if trimmed.starts_with("import ")
            || trimmed.starts_with("const ") && trimmed.contains("require(")
        {
            if let Some(imp) = parse_js_import(trimmed, line_num) {
                imports.push(imp);
            }
            continue;
        }

        // Function start: function foo(...), const foo = (...) =>, async function
        if current_fn.is_none()
            && (trimmed.contains("function ")
                || trimmed.contains("=>")
                || trimmed.starts_with("async "))
        {
            if let Some((name, params)) = parse_js_function_sig(trimmed) {
                fn_brace_start = brace_depth;
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

        // Assignments
        if let Some(assign) = parse_js_assignment(trimmed, line_num) {
            if let Some(ref mut fn_node) = current_fn {
                fn_node.assignments.push(assign);
            }
        }

        // Call sites
        if let Some(calls) = extract_js_calls(trimmed, line_num, &indent_str) {
            for call in calls {
                if let Some(ref mut fn_node) = current_fn {
                    fn_node.calls.push(call);
                } else {
                    global_calls.push(call);
                }
            }
        }

        // Brace counting to track function boundaries
        for ch in trimmed.chars() {
            if ch == '{' {
                brace_depth += 1;
            } else if ch == '}' {
                brace_depth = brace_depth.saturating_sub(1);
                if let Some(mut fn_node) = current_fn.take() {
                    if brace_depth <= fn_brace_start {
                        fn_node.end_line = line_num;
                        functions.push(fn_node);
                    } else {
                        current_fn = Some(fn_node);
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
        language: lang,
        lines,
        imports,
        functions,
        global_calls,
    })
}

fn parse_js_import(line: &str, line_num: usize) -> Option<AstImport> {
    if line.starts_with("import ") {
        // import x from 'y'; or import { a, b } from 'y';
        if let Some((_, from_part)) = line.split_once(" from ") {
            let module = from_part
                .trim_matches(|c| c == '\'' || c == '"' || c == ';' || c == ' ')
                .to_string();
            Some(AstImport {
                module,
                alias: None,
                items: Vec::new(),
                line: line_num,
                is_esm: true,
            })
        } else {
            None
        }
    } else if line.contains("require(") {
        // const x = require('y'); or const { a } = require('y');
        if let Some((lhs, rhs)) = line.split_once('=') {
            if let Some(open_req) = rhs.find("require(") {
                let req_slice = &rhs[open_req + 8..];
                if let Some(close_req) = req_slice.find(')') {
                    let module = req_slice[..close_req]
                        .trim_matches(|c| c == '\'' || c == '"' || c == ' ')
                        .to_string();
                    let items = if lhs.contains('{') {
                        lhs.trim_matches(|c| {
                            c == '{'
                                || c == '}'
                                || c == ' '
                                || c == ';'
                                || c == 'c'
                                || c == 'o'
                                || c == 'n'
                                || c == 's'
                                || c == 't'
                        })
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                    } else {
                        vec![lhs
                            .trim()
                            .replace("const ", "")
                            .replace("let ", "")
                            .replace("var ", "")
                            .trim()
                            .to_string()]
                    };
                    return Some(AstImport {
                        module,
                        alias: None,
                        items,
                        line: line_num,
                        is_esm: false,
                    });
                }
            }
        }
        None
    } else {
        None
    }
}

fn parse_js_function_sig(line: &str) -> Option<(String, Vec<String>)> {
    if let Some(stripped) = line.strip_prefix("function ") {
        let (name_part, rest) = stripped.split_once('(')?;
        let name = name_part.trim().to_string();
        let (params_part, _) = rest.split_once(')')?;
        let params = parse_js_params(params_part);
        Some((name, params))
    } else if line.contains("=>") {
        let (lhs, _) = line.split_once("=>")?;
        let (name, params_str) = if let Some((var_part, args_part)) = lhs.split_once('=') {
            let var_name = var_part
                .replace("const ", "")
                .replace("let ", "")
                .replace("var ", "")
                .trim()
                .to_string();
            (var_name, args_part.trim())
        } else {
            ("anonymous".to_string(), lhs.trim())
        };
        let params_clean = params_str.trim_matches(|c| c == '(' || c == ')' || c == ' ');
        let params = parse_js_params(params_clean);
        Some((name, params))
    } else {
        None
    }
}

fn parse_js_params(params_str: &str) -> Vec<String> {
    params_str
        .split(',')
        .map(|p| {
            let clean = p.trim();
            // remove TS type annotations param: string
            clean.split(':').next().unwrap_or("").trim().to_string()
        })
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_js_assignment(line: &str, line_num: usize) -> Option<AstAssignment> {
    if !line.contains('=') || line.contains("==") || line.contains("=>") {
        return None;
    }
    let (lhs, rhs) = line.split_once('=')?;
    let var = lhs
        .replace("const ", "")
        .replace("let ", "")
        .replace("var ", "")
        .trim()
        .to_string();
    if var.is_empty() || var.contains('(') || var.contains(' ') {
        return None;
    }
    Some(AstAssignment {
        variable: var,
        expression: rhs.trim_end_matches(';').trim().to_string(),
        line: line_num,
    })
}

fn extract_js_calls(line: &str, line_num: usize, indent_str: &str) -> Option<Vec<AstCallSite>> {
    let mut calls = Vec::new();
    let targets = [
        "db.query",
        "pool.query",
        "client.query",
        "child_process.exec",
        "child_process.execSync",
        "child_process.execFile",
        "exec(",
        "fs.readFile",
        "fs.readFileSync",
        "fs.createReadStream",
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

        if ch == '\'' || ch == '"' || ch == '`' {
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

use crate::error::FixError;
use crate::models::{
    AstCallSite, AstFunction, ParsedSourceFile, SanitizerKind, SourceLanguage, TaintFlowPath,
    TaintSinkKind, TaintSourceKind,
};
use crate::taint::rules::{
    check_sanitizer, identify_taint_source, COMMAND_INJECTION_RULE, PATH_TRAVERSAL_RULE,
    SQL_INJECTION_RULE,
};
use crate::traits::TaintAnalyzer;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct DefaultTaintAnalyzer;

impl DefaultTaintAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl TaintAnalyzer for DefaultTaintAnalyzer {
    fn analyze(&self, ast: &ParsedSourceFile) -> Result<Vec<TaintFlowPath>, FixError> {
        let mut flows = Vec::new();

        // 1. Analyze function scopes
        for func in &ast.functions {
            let fn_flows = analyze_function(func, ast.language);
            flows.extend(fn_flows);
        }

        // 2. Analyze global calls
        for call in &ast.global_calls {
            if let Some(flow) = analyze_standalone_call(call, ast.language) {
                flows.push(flow);
            }
        }

        // 3. Scan for Hardcoded Secrets
        let secret_flows = scan_hardcoded_secrets(ast);
        flows.extend(secret_flows);

        Ok(flows)
    }
}

fn analyze_function(func: &AstFunction, lang: SourceLanguage) -> Vec<TaintFlowPath> {
    let mut flows = Vec::new();
    let mut tainted_vars: HashMap<String, (TaintSourceKind, usize, Vec<String>)> = HashMap::new();
    let mut sanitized_vars: HashSet<String> = HashSet::new();

    // Check function parameters
    for param in &func.parameters {
        let p_lower = param.to_ascii_lowercase();
        if p_lower.contains("user")
            || p_lower.contains("query")
            || p_lower.contains("param")
            || p_lower.contains("req")
            || p_lower.contains("input")
            || p_lower.contains("id")
            || p_lower.contains("path")
            || p_lower.contains("file")
            || p_lower.contains("cmd")
        {
            tainted_vars.insert(
                param.clone(),
                (
                    TaintSourceKind::HttpQueryParam,
                    func.start_line,
                    vec![param.clone()],
                ),
            );
        }
    }

    // Trace assignments
    for assign in &func.assignments {
        // If RHS is a direct taint source
        if let Some((source_kind, src_id)) = identify_taint_source(&assign.expression) {
            tainted_vars.insert(
                assign.variable.clone(),
                (source_kind, assign.line, vec![src_id]),
            );
            continue;
        }

        // Check if RHS derives from an existing tainted variable
        for (t_var, (src_kind, src_line, props)) in &tainted_vars.clone() {
            if assign.expression.contains(t_var) {
                // Check if sanitized
                if let Some(_sanitizer) =
                    check_sanitizer(&assign.expression, TaintSinkKind::SqlExecution)
                {
                    sanitized_vars.insert(assign.variable.clone());
                } else if let Some(_sanitizer) =
                    check_sanitizer(&assign.expression, TaintSinkKind::CommandExecution)
                {
                    sanitized_vars.insert(assign.variable.clone());
                } else if let Some(_sanitizer) =
                    check_sanitizer(&assign.expression, TaintSinkKind::PathTraversal)
                {
                    sanitized_vars.insert(assign.variable.clone());
                } else {
                    let mut new_props = props.clone();
                    new_props.push(format!("{} = {}", assign.variable, assign.expression));
                    tainted_vars.insert(assign.variable.clone(), (*src_kind, *src_line, new_props));
                }
            }
        }
    }

    // Evaluate calls
    for call in &func.calls {
        if let Some(flow) = evaluate_call(call, &tainted_vars, &sanitized_vars, lang) {
            flows.push(flow);
        }
    }

    flows
}

fn evaluate_call(
    call: &AstCallSite,
    tainted_vars: &HashMap<String, (TaintSourceKind, usize, Vec<String>)>,
    sanitized_vars: &HashSet<String>,
    _lang: SourceLanguage,
) -> Option<TaintFlowPath> {
    // 1. SQL Injection check
    if SQL_INJECTION_RULE
        .sink_indicators
        .iter()
        .any(|sink| call.callee.contains(sink))
    {
        if let Some(first_arg) = call.raw_args.first() {
            // Is it an interpolated string or concatenation?
            let is_interpolated = first_arg.starts_with("f\"")
                || first_arg.starts_with("f'")
                || first_arg.contains('+')
                || first_arg.contains('`')
                || first_arg.contains("Sprintf(")
                || first_arg.contains("format!(");

            for (t_var, (src_kind, src_line, props)) in tainted_vars {
                if first_arg.contains(t_var) && !sanitized_vars.contains(t_var) {
                    let is_sanitized = call.raw_args.len() > 1
                        || check_sanitizer(first_arg, TaintSinkKind::SqlExecution).is_some();
                    return Some(TaintFlowPath {
                        source_kind: *src_kind,
                        source_identifier: t_var.clone(),
                        source_line: *src_line,
                        propagators: props.clone(),
                        sink_kind: TaintSinkKind::SqlExecution,
                        sink_call: call.callee.clone(),
                        sink_line: call.line,
                        is_sanitized,
                        sanitizer_kind: if is_sanitized {
                            Some(SanitizerKind::ParameterizedQuery)
                        } else {
                            None
                        },
                    });
                }
            }

            if is_interpolated && call.raw_args.len() == 1 {
                return Some(TaintFlowPath {
                    source_kind: TaintSourceKind::HttpQueryParam,
                    source_identifier: first_arg.clone(),
                    source_line: call.line,
                    propagators: vec![],
                    sink_kind: TaintSinkKind::SqlExecution,
                    sink_call: call.callee.clone(),
                    sink_line: call.line,
                    is_sanitized: false,
                    sanitizer_kind: None,
                });
            }
        }
    }

    // 2. Command Injection check
    if COMMAND_INJECTION_RULE
        .sink_indicators
        .iter()
        .any(|sink| call.callee.contains(sink))
    {
        let has_shell_true = call
            .raw_args
            .iter()
            .any(|arg| arg.contains("shell=True") || arg.contains("shell = True"));
        let is_direct_exec = call.callee.contains("exec")
            || call.callee.contains("system")
            || call.callee.contains("Command");

        for arg in &call.raw_args {
            for (t_var, (src_kind, src_line, props)) in tainted_vars {
                if arg.contains(t_var) && (has_shell_true || is_direct_exec) {
                    let is_sanitized =
                        check_sanitizer(arg, TaintSinkKind::CommandExecution).is_some();
                    return Some(TaintFlowPath {
                        source_kind: *src_kind,
                        source_identifier: t_var.clone(),
                        source_line: *src_line,
                        propagators: props.clone(),
                        sink_kind: TaintSinkKind::CommandExecution,
                        sink_call: call.callee.clone(),
                        sink_line: call.line,
                        is_sanitized,
                        sanitizer_kind: if is_sanitized {
                            Some(SanitizerKind::ShellQuoteOrArgArray)
                        } else {
                            None
                        },
                    });
                }
            }
        }

        if let Some(first_arg) = call.raw_args.first() {
            if has_shell_true
                || (is_direct_exec
                    && (first_arg.contains('+')
                        || first_arg.contains("f\"")
                        || first_arg.contains('`')))
            {
                return Some(TaintFlowPath {
                    source_kind: TaintSourceKind::CliArgument,
                    source_identifier: first_arg.clone(),
                    source_line: call.line,
                    propagators: vec![],
                    sink_kind: TaintSinkKind::CommandExecution,
                    sink_call: call.callee.clone(),
                    sink_line: call.line,
                    is_sanitized: false,
                    sanitizer_kind: None,
                });
            }
        }
    }

    // 3. Path Traversal check
    if PATH_TRAVERSAL_RULE
        .sink_indicators
        .iter()
        .any(|sink| call.callee.contains(sink))
    {
        if let Some(first_arg) = call.raw_args.first() {
            for (t_var, (src_kind, src_line, props)) in tainted_vars {
                if first_arg.contains(t_var) && !sanitized_vars.contains(t_var) {
                    let is_sanitized =
                        check_sanitizer(first_arg, TaintSinkKind::PathTraversal).is_some();
                    return Some(TaintFlowPath {
                        source_kind: *src_kind,
                        source_identifier: t_var.clone(),
                        source_line: *src_line,
                        propagators: props.clone(),
                        sink_kind: TaintSinkKind::PathTraversal,
                        sink_call: call.callee.clone(),
                        sink_line: call.line,
                        is_sanitized,
                        sanitizer_kind: if is_sanitized {
                            Some(SanitizerKind::PathContainmentGuard)
                        } else {
                            None
                        },
                    });
                }
            }
        }
    }

    None
}

fn analyze_standalone_call(call: &AstCallSite, lang: SourceLanguage) -> Option<TaintFlowPath> {
    let empty_map = HashMap::new();
    let empty_set = HashSet::new();
    evaluate_call(call, &empty_map, &empty_set, lang)
}

fn scan_hardcoded_secrets(ast: &ParsedSourceFile) -> Vec<TaintFlowPath> {
    let mut flows = Vec::new();
    let secret_keywords = [
        "_KEY",
        "_SECRET",
        "_TOKEN",
        "_PASSWORD",
        "API_KEY",
        "SECRET_KEY",
    ];

    for (idx, line) in ast.lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        for kw in &secret_keywords {
            if trimmed.contains(kw) && trimmed.contains('=') && !trimmed.contains("==") {
                if let Some((lhs, rhs)) = trimmed.split_once('=') {
                    let var = lhs.trim();
                    let val = rhs.trim().trim_end_matches(';').trim();
                    // If assigned a non-empty string literal
                    if (val.starts_with('"') && val.ends_with('"') && val.len() > 8)
                        || (val.starts_with('\'') && val.ends_with('\'') && val.len() > 8)
                    {
                        // Check if it's already an env lookup
                        if !val.contains("environ")
                            && !val.contains("getenv")
                            && !val.contains("process.env")
                            && !val.contains("std::env::var")
                        {
                            flows.push(TaintFlowPath {
                                source_kind: TaintSourceKind::EnvironmentVariable,
                                source_identifier: var.to_string(),
                                source_line: line_num,
                                propagators: vec![],
                                sink_kind: TaintSinkKind::HardcodedSecret,
                                sink_call: format!("{} = {}", var, val),
                                sink_line: line_num,
                                is_sanitized: false,
                                sanitizer_kind: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    flows
}

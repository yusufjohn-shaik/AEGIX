//! Zero-dependency deterministic Rust lexer and multi-source BFS call-graph reachability engine.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{DependencyScope, ReachabilityStatus, WorkspaceDependencyGraph};
use crate::traits::{FunctionReachabilitySpan, ReachabilityAnalyzer, RustReachabilityIndex};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_RS_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB safety cap

#[derive(Debug, Default, Clone)]
pub struct RustCallGraphAnalyzer;

impl RustCallGraphAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Collects workspace `.rs` files bounded by symlink-cycle protection and size caps.
    fn collect_workspace_files(
        dep_graph: &WorkspaceDependencyGraph,
        target: &Path,
    ) -> BTreeMap<PathBuf, (String, bool, bool)> {
        // Maps canonical/absolute path -> (rel_display_path, is_library_crate, is_test_dir)
        let mut files: BTreeMap<PathBuf, (String, bool, bool)> = BTreeMap::new();

        let scan_dirs: Vec<(PathBuf, bool)> = if !dep_graph.target_roots.is_empty() {
            let mut dirs: BTreeMap<PathBuf, bool> = BTreeMap::new();
            for root in &dep_graph.target_roots {
                let entry = dirs.entry(root.manifest_dir.clone()).or_insert(false);
                if root.is_library {
                    *entry = true;
                }
            }
            dirs.into_iter().collect()
        } else if target.is_dir() {
            vec![(target.to_path_buf(), false)]
        } else if target.is_file() && target.extension().is_some_and(|e| e == "rs") {
            let parent = target.parent().unwrap_or(target).to_path_buf();
            vec![(parent, false)]
        } else {
            Vec::new()
        };

        let root_base = if dep_graph.workspace_root.exists() {
            dep_graph.workspace_root.as_path()
        } else {
            target
        };

        for (dir, is_lib) in scan_dirs {
            if !dir.exists() {
                continue;
            }
            for entry in WalkDir::new(&dir)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with('.')
                        && name != "target"
                        && name != "node_modules"
                        && name != "vendor"
                })
                .flatten()
            {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                    if let Ok(meta) = entry.metadata() {
                        if meta.len() > MAX_RS_FILE_BYTES {
                            continue;
                        }
                    }

                    let rel_to_crate = path.strip_prefix(&dir).unwrap_or(path);
                    let is_test_dir = rel_to_crate.components().any(|c| {
                        let s = c.as_os_str().to_string_lossy();
                        matches!(s.as_ref(), "tests" | "benches" | "examples")
                    });

                    let rel_display = path
                        .strip_prefix(root_base)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");

                    let entry = files
                        .entry(path.to_path_buf())
                        .or_insert_with(|| (rel_display, is_lib, is_test_dir));
                    if is_lib {
                        entry.1 = true;
                    }
                }
            }
        }

        files
    }
}

impl ReachabilityAnalyzer for RustCallGraphAnalyzer {
    fn analyze(
        &self,
        dep_graph: &WorkspaceDependencyGraph,
        target: &Path,
    ) -> Result<RustReachabilityIndex, RiskError> {
        let mut index = RustReachabilityIndex::default();

        // Map every known dependency import_ident -> set of canonical Cargo crate names
        let mut ident_to_crates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (crate_name, dep_node) in &dep_graph.packages {
            if dep_node.is_workspace_member {
                continue;
            }
            for ident in &dep_node.import_idents {
                ident_to_crates
                    .entry(ident.clone())
                    .or_default()
                    .insert(crate_name.clone());
            }
        }

        let workspace_files = Self::collect_workspace_files(dep_graph, target);

        let mut parsed_functions: BTreeMap<String, ParsedFunction> = BTreeMap::new();
        let mut short_name_to_qual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut prod_imported_idents: BTreeSet<String> = BTreeSet::new();
        let mut test_imported_idents: BTreeSet<String> = BTreeSet::new();

        for (file_path, (rel_path, is_lib, is_test_dir)) in workspace_files {
            let Ok(content) = std::fs::read_to_string(&file_path) else {
                continue;
            };
            let tokens = tokenize_rust(&content);
            let parsed =
                parse_file_tokens(&tokens, &rel_path, is_lib, is_test_dir, &ident_to_crates);

            prod_imported_idents.extend(parsed.prod_crate_refs);
            test_imported_idents.extend(parsed.test_crate_refs);

            for func in parsed.functions {
                short_name_to_qual
                    .entry(func.fn_name.clone())
                    .or_default()
                    .insert(func.qual_name.clone());
                parsed_functions.insert(func.qual_name.clone(), func);
            }
        }

        index.analyzed_functions = parsed_functions.len();

        // Build sorted adjacency graph over workspace functions
        let mut fn_adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut entrypoints: BTreeSet<String> = BTreeSet::new();

        for (qual_name, func) in &parsed_functions {
            if func.is_entrypoint {
                entrypoints.insert(qual_name.clone());
            }
            let callees = fn_adj.entry(qual_name.clone()).or_default();
            for short_callee in &func.intra_calls {
                if let Some(targets) = short_name_to_qual.get(short_callee) {
                    for t in targets {
                        if t != qual_name {
                            callees.insert(t.clone());
                        }
                    }
                }
            }
        }

        // Single-pass O(V + E) deterministic multi-source BFS from all production entrypoints
        let mut parent_map: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        for ep in &entrypoints {
            parent_map.insert(ep.clone(), None);
            queue.push_back(ep.clone());
        }

        while let Some(curr) = queue.pop_front() {
            if let Some(neighbors) = fn_adj.get(&curr) {
                for next in neighbors {
                    if !parent_map.contains_key(next) {
                        parent_map.insert(next.clone(), Some(curr.clone()));
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        // Reconstruct deterministic entrypoint traces for all functions and external crate calls
        // Map external import_ident -> best (shortest) call trace
        let mut best_trace_by_ident: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (qual_name, func) in &parsed_functions {
            let trace = if parent_map.contains_key(qual_name) {
                Some(reconstruct_trace(qual_name, &parent_map))
            } else {
                None
            };

            index
                .function_spans
                .entry(func.rel_path.clone())
                .or_default()
                .push(FunctionReachabilitySpan {
                    start_line: func.start_line,
                    end_line: func.end_line,
                    qual_name: qual_name.clone(),
                    is_test_scope: func.is_test_scope,
                    entrypoint_trace: trace.clone(),
                });

            if let Some(fn_trace) = trace {
                if !func.is_test_scope {
                    for (dep_ident, call_expr) in &func.ext_calls {
                        let mut full_trace = fn_trace.clone();
                        full_trace.push(call_expr.clone());

                        let should_replace = match best_trace_by_ident.get(dep_ident) {
                            Some(existing) => {
                                full_trace.len() < existing.len()
                                    || (full_trace.len() == existing.len()
                                        && full_trace < *existing)
                            }
                            None => true,
                        };
                        if should_replace {
                            best_trace_by_ident.insert(dep_ident.clone(), full_trace);
                        }
                    }
                }
            }
        }

        // Ensure deterministic sorting of spans per file
        for spans in index.function_spans.values_mut() {
            spans.sort_by_key(|s| (s.start_line, s.end_line));
        }

        // Classify every dependency in WorkspaceDependencyGraph
        for (crate_name, dep_node) in &dep_graph.packages {
            if dep_node.is_workspace_member {
                continue;
            }

            // 1. Check VerifiedReachable (trace from production entrypoint to external call site)
            let mut best_call_trace: Option<Vec<String>> = None;
            for ident in &dep_node.import_idents {
                if let Some(trace) = best_trace_by_ident.get(ident) {
                    let replace = match &best_call_trace {
                        Some(existing) => trace.len() < existing.len(),
                        None => true,
                    };
                    if replace {
                        best_call_trace = Some(trace.clone());
                    }
                }
            }

            if let Some(trace) = best_call_trace {
                let is_dev_only = matches!(
                    dep_node.scope,
                    DependencyScope::DevDirect | DependencyScope::DevTransitive
                );
                if !is_dev_only {
                    let ev = format!(
                        "Verified entrypoint call path to '{}': {}",
                        crate_name,
                        trace.join(" -> ")
                    );
                    index.crate_reachability.insert(
                        crate_name.clone(),
                        (ReachabilityStatus::VerifiedReachable, trace, ev),
                    );
                    continue;
                }
            }

            // 2. Check ImportedInSource in non-test production code
            let imported_in_prod = dep_node
                .import_idents
                .iter()
                .any(|id| prod_imported_idents.contains(id));

            if imported_in_prod
                && !matches!(
                    dep_node.scope,
                    DependencyScope::DevDirect | DependencyScope::DevTransitive
                )
            {
                let ev = format!(
                    "Crate '{}' is imported or referenced directly in production source",
                    crate_name
                );
                index.crate_reachability.insert(
                    crate_name.clone(),
                    (ReachabilityStatus::ImportedInSource, Vec::new(), ev),
                );
                continue;
            }

            // 3. Classify remaining dependencies strictly by Cargo dependency graph scope
            let (status, ev) = match dep_node.scope {
                DependencyScope::NormalDirect => (
                    ReachabilityStatus::DirectDeclared,
                    format!(
                        "Direct normal dependency '{}' declared in Cargo.toml",
                        crate_name
                    ),
                ),
                DependencyScope::BuildDirect | DependencyScope::BuildTransitive => (
                    ReachabilityStatus::BuildDependency,
                    format!(
                        "Build dependency '{}' executes at compile time (build.rs / codegen)",
                        crate_name
                    ),
                ),
                DependencyScope::NormalTransitive => {
                    let parents: Vec<String> = dep_node.depended_by.iter().cloned().collect();
                    let chain_hint = if parents.is_empty() {
                        "active normal parent".to_string()
                    } else {
                        parents.join(", ")
                    };
                    (
                        ReachabilityStatus::TransitiveReachable,
                        format!(
                            "Transitive normal dependency '{}' required by {}",
                            crate_name, chain_hint
                        ),
                    )
                }
                DependencyScope::DevDirect | DependencyScope::DevTransitive => (
                    ReachabilityStatus::DevOrTestOnly,
                    format!(
                        "Dependency '{}' is confined exclusively to dev/test targets",
                        crate_name
                    ),
                ),
                DependencyScope::Orphaned => {
                    if dep_node.is_proc_macro {
                        (
                            ReachabilityStatus::DirectDeclared,
                            format!(
                                "Proc-macro crate '{}' executes during compilation",
                                crate_name
                            ),
                        )
                    } else if test_imported_idents
                        .iter()
                        .any(|id| dep_node.import_idents.contains(id))
                    {
                        (
                            ReachabilityStatus::DevOrTestOnly,
                            format!("Crate '{}' referenced only in test modules", crate_name),
                        )
                    } else {
                        (
                            ReachabilityStatus::Unreachable,
                            format!(
                                "Orphaned package '{}' has no active edge from production dependencies",
                                crate_name
                            ),
                        )
                    }
                }
            };

            index
                .crate_reachability
                .insert(crate_name.clone(), (status, Vec::new(), ev));
        }

        Ok(index)
    }
}

fn reconstruct_trace(target: &str, parent_map: &BTreeMap<String, Option<String>>) -> Vec<String> {
    let mut rev_path = Vec::new();
    let mut curr = Some(target.to_string());
    let mut safety_guard = 0usize;

    while let Some(node) = curr {
        rev_path.push(node.clone());
        curr = parent_map.get(&node).and_then(|p| p.clone());
        safety_guard += 1;
        if safety_guard > 256 {
            break;
        }
    }
    rev_path.reverse();
    rev_path
}

// --- Zero-Dependency Deterministic Rust Lexer & Brace-Depth Parser ---

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    ColonColon,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Semi,
    Hash,
    Bang,
    Comma,
    Other(char),
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    line: usize,
}

fn tokenize_rust(src: &str) -> Vec<Token> {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut tokens = Vec::new();

    while i < len {
        let b = bytes[i];

        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }

        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Line comment //
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            i += 2;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Nested block comment /* ... */
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            let mut depth = 1usize;
            while i < len && depth > 0 {
                if bytes[i] == b'\n' {
                    line += 1;
                } else if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 1;
                } else if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 1;
                }
                i += 1;
            }
            continue;
        }

        // Raw string literals r#"..."# / r"..." / br#"..."#
        if (b == b'r' || (b == b'b' && i + 1 < len && bytes[i + 1] == b'r'))
            && is_raw_string_start(bytes, i)
        {
            let mut pos = if b == b'b' { i + 2 } else { i + 1 };
            let mut hashes = 0usize;
            while pos < len && bytes[pos] == b'#' {
                hashes += 1;
                pos += 1;
            }
            if pos < len && bytes[pos] == b'"' {
                pos += 1;
                while pos < len {
                    if bytes[pos] == b'\n' {
                        line += 1;
                    } else if bytes[pos] == b'"' {
                        let mut matched = 0usize;
                        while matched < hashes
                            && pos + 1 + matched < len
                            && bytes[pos + 1 + matched] == b'#'
                        {
                            matched += 1;
                        }
                        if matched == hashes {
                            pos += 1 + hashes;
                            break;
                        }
                    }
                    pos += 1;
                }
                i = pos;
                continue;
            }
        }

        // Standard string / byte string literal
        if b == b'"' || (b == b'b' && i + 1 < len && bytes[i + 1] == b'"') {
            i += if b == b'b' { 2 } else { 1 };
            while i < len {
                if bytes[i] == b'\n' {
                    line += 1;
                } else if bytes[i] == b'\\' {
                    i += 1;
                    if i < len && bytes[i] == b'\n' {
                        line += 1;
                    }
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Character / byte literal vs lifetime `'a`
        if b == b'\'' || (b == b'b' && i + 1 < len && bytes[i + 1] == b'\'') {
            let start = if b == b'b' { i + 2 } else { i + 1 };
            if start < len {
                if bytes[start] == b'\\' {
                    // Escaped char literal e.g. '\n' or '\''
                    i = start + 1;
                    while i < len && bytes[i] != b'\'' && bytes[i] != b'\n' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    if i < len && bytes[i] == b'\'' {
                        i += 1;
                    }
                    continue;
                } else if start + 1 < len && bytes[start + 1] == b'\'' {
                    // Single ASCII char literal like 'a'
                    i = start + 2;
                    continue;
                } else if let Some(ch_end) = check_utf8_char_literal(bytes, start) {
                    i = ch_end;
                    continue;
                }
            }
            // Otherwise it is a lifetime (`'a` / `'static`); skip `'` cleanly
            i += 1;
            continue;
        }

        // Two-char `::`
        if b == b':' && i + 1 < len && bytes[i + 1] == b':' {
            tokens.push(Token {
                kind: TokenKind::ColonColon,
                line,
            });
            i += 2;
            continue;
        }

        // Identifier
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = String::from_utf8_lossy(&bytes[start..i]).to_string();
            tokens.push(Token {
                kind: TokenKind::Ident(word),
                line,
            });
            continue;
        }

        // Single-char punctuation
        let kind = match b {
            b'{' => TokenKind::LBrace,
            b'}' => TokenKind::RBrace,
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b';' => TokenKind::Semi,
            b'#' => TokenKind::Hash,
            b'!' => TokenKind::Bang,
            b',' => TokenKind::Comma,
            other => TokenKind::Other(other as char),
        };
        tokens.push(Token { kind, line });
        i += 1;
    }

    tokens
}

fn is_raw_string_start(bytes: &[u8], idx: usize) -> bool {
    let mut pos = if bytes[idx] == b'b' { idx + 2 } else { idx + 1 };
    while pos < bytes.len() && bytes[pos] == b'#' {
        pos += 1;
    }
    pos < bytes.len() && bytes[pos] == b'"'
}

fn check_utf8_char_literal(bytes: &[u8], start: usize) -> Option<usize> {
    let slice = &bytes[start..bytes.len().min(start + 6)];
    let s = std::str::from_utf8(slice).ok()?;
    let mut chars = s.chars();
    let ch = chars.next()?;
    let ch_len = ch.len_utf8();
    if start + ch_len < bytes.len() && bytes[start + ch_len] == b'\'' {
        Some(start + ch_len + 1)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct ParsedFunction {
    rel_path: String,
    fn_name: String,
    qual_name: String,
    start_line: usize,
    end_line: usize,
    is_test_scope: bool,
    is_entrypoint: bool,
    intra_calls: BTreeSet<String>,
    ext_calls: BTreeSet<(String, String)>, // (dep_ident, display_call)
}

#[derive(Debug, Default)]
struct ParsedFileResult {
    functions: Vec<ParsedFunction>,
    prod_crate_refs: BTreeSet<String>,
    test_crate_refs: BTreeSet<String>,
}

fn parse_file_tokens(
    tokens: &[Token],
    rel_path: &str,
    is_lib: bool,
    is_test_dir: bool,
    known_dep_idents: &BTreeMap<String, BTreeSet<String>>,
) -> ParsedFileResult {
    let mut res = ParsedFileResult::default();
    let n = tokens.len();
    let mut i = 0usize;

    // Brace stack stores `is_test_scope` inherited from outer blocks
    let mut brace_test_stack: Vec<bool> = vec![is_test_dir];
    let mut pending_test_attr = false;
    let mut pending_entrypoint_attr = false;
    let mut pending_pub = false;
    let mut seen_fn_names: BTreeMap<String, usize> = BTreeMap::new();

    // Local symbol -> root dep crate ident inside this file
    let mut prod_symbol_to_crate: BTreeMap<String, String> = BTreeMap::new();
    let mut test_symbol_to_crate: BTreeMap<String, String> = BTreeMap::new();

    while i < n {
        let in_test_scope = *brace_test_stack.last().unwrap_or(&is_test_dir);

        match &tokens[i].kind {
            // Attribute `#[...]`
            TokenKind::Hash if i + 1 < n && matches!(tokens[i + 1].kind, TokenKind::LBracket) => {
                let mut depth = 0usize;
                let mut attr_words = Vec::new();
                i += 1;
                while i < n {
                    match &tokens[i].kind {
                        TokenKind::LBracket => depth += 1,
                        TokenKind::RBracket => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        TokenKind::Ident(w) => attr_words.push(w.clone()),
                        _ => {}
                    }
                    i += 1;
                }
                if attr_words.iter().any(|w| w == "test")
                    || (attr_words.contains(&"cfg".to_string())
                        && attr_words.contains(&"test".to_string()))
                {
                    pending_test_attr = true;
                }
                if attr_words.iter().any(|w| {
                    matches!(
                        w.as_str(),
                        "main"
                            | "debug_handler"
                            | "get"
                            | "post"
                            | "put"
                            | "delete"
                            | "patch"
                            | "route"
                    )
                }) {
                    pending_entrypoint_attr = true;
                }
                continue;
            }

            // `pub` modifier tracking (reset on `;` or `{`)
            TokenKind::Ident(w) if w == "pub" => {
                pending_pub = true;
                // Skip optional `(crate)` / `(super)` visibility restriction
                if i + 1 < n && matches!(tokens[i + 1].kind, TokenKind::LParen) {
                    let mut pdepth = 0usize;
                    let mut is_restricted = false;
                    let mut j = i + 1;
                    while j < n {
                        match &tokens[j].kind {
                            TokenKind::LParen => pdepth += 1,
                            TokenKind::RParen => {
                                pdepth = pdepth.saturating_sub(1);
                                if pdepth == 0 {
                                    i = j;
                                    break;
                                }
                            }
                            TokenKind::Ident(vis)
                                if vis == "crate" || vis == "super" || vis == "in" =>
                            {
                                is_restricted = true;
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                    if is_restricted {
                        pending_pub = false;
                    }
                }
                i += 1;
                continue;
            }

            // `use ...;` statement
            TokenKind::Ident(w) if w == "use" => {
                i += 1;
                let start = i;
                while i < n && !matches!(tokens[i].kind, TokenKind::Semi | TokenKind::RBrace) {
                    i += 1;
                }
                let slice = &tokens[start..i];
                let (crates_used, symbol_pairs) = extract_use_bindings(slice);
                for c in crates_used {
                    if known_dep_idents.contains_key(&c) {
                        if in_test_scope {
                            res.test_crate_refs.insert(c);
                        } else {
                            res.prod_crate_refs.insert(c);
                        }
                    }
                }
                for (sym, root_crate) in symbol_pairs {
                    if known_dep_idents.contains_key(&root_crate) {
                        if in_test_scope {
                            test_symbol_to_crate.insert(sym, root_crate);
                        } else {
                            prod_symbol_to_crate.insert(sym, root_crate);
                        }
                    }
                }
                pending_pub = false;
                if i < n && matches!(tokens[i].kind, TokenKind::Semi) {
                    i += 1;
                }
                continue;
            }

            // `extern crate foo [as bar];`
            TokenKind::Ident(w)
                if w == "extern"
                    && i + 2 < n
                    && matches!(&tokens[i + 1].kind, TokenKind::Ident(c) if c == "crate") =>
            {
                if let TokenKind::Ident(crate_ident) = &tokens[i + 2].kind {
                    if known_dep_idents.contains_key(crate_ident) {
                        if in_test_scope {
                            res.test_crate_refs.insert(crate_ident.clone());
                        } else {
                            res.prod_crate_refs.insert(crate_ident.clone());
                        }
                        if i + 4 < n
                            && matches!(&tokens[i + 3].kind, TokenKind::Ident(a) if a == "as")
                        {
                            if let TokenKind::Ident(alias_ident) = &tokens[i + 4].kind {
                                if in_test_scope {
                                    test_symbol_to_crate
                                        .insert(alias_ident.clone(), crate_ident.clone());
                                } else {
                                    prod_symbol_to_crate
                                        .insert(alias_ident.clone(), crate_ident.clone());
                                }
                            }
                        }
                    }
                }
                i += 1;
                continue;
            }

            // `mod name { ... }` inheriting pending_test_attr
            TokenKind::Ident(w) if w == "mod" => {
                let is_test_mod = in_test_scope || pending_test_attr;
                pending_test_attr = false;
                pending_pub = false;
                let mut j = i + 1;
                while j < n && !matches!(tokens[j].kind, TokenKind::LBrace | TokenKind::Semi) {
                    j += 1;
                }
                if j < n && matches!(tokens[j].kind, TokenKind::LBrace) {
                    brace_test_stack.push(is_test_mod);
                    i = j + 1;
                    continue;
                }
                i = j + 1;
                continue;
            }

            // Function declaration `fn <name>(...) ... { body }`
            TokenKind::Ident(w) if w == "fn" && i + 1 < n => {
                let start_line = tokens[i].line;
                let fn_is_test = in_test_scope || pending_test_attr;
                let fn_is_entrypoint = !fn_is_test
                    && (matches!(&tokens[i + 1].kind, TokenKind::Ident(name) if name == "main")
                        || pending_entrypoint_attr
                        || (is_lib && pending_pub));

                pending_test_attr = false;
                pending_entrypoint_attr = false;
                pending_pub = false;

                let TokenKind::Ident(fn_name) = &tokens[i + 1].kind else {
                    i += 1;
                    continue;
                };
                let fn_name = fn_name.clone();

                // Advance to function body `{` (ignoring trait signatures ending with `;`)
                let mut j = i + 2;
                let mut found_brace = false;
                while j < n {
                    match &tokens[j].kind {
                        TokenKind::LBrace => {
                            // Ensure it's not inside `where` trait bound braces or type param defaults
                            found_brace = true;
                            break;
                        }
                        TokenKind::Semi => break,
                        _ => j += 1,
                    }
                }

                if !found_brace {
                    i = j + 1;
                    continue;
                }

                // Extract balanced body slice
                let body_start = j + 1;
                let mut depth = 1usize;
                let mut k = body_start;
                while k < n && depth > 0 {
                    match &tokens[k].kind {
                        TokenKind::LBrace => depth += 1,
                        TokenKind::RBrace => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                    k += 1;
                }
                let end_line = if k < n { tokens[k].line } else { start_line };
                let body_slice = &tokens[body_start..k.min(n)];

                let sym_map = if fn_is_test {
                    &test_symbol_to_crate
                } else {
                    &prod_symbol_to_crate
                };

                let (intra_calls, ext_calls, inline_crate_refs) =
                    scan_function_body(body_slice, known_dep_idents, sym_map);

                if !fn_is_test {
                    res.prod_crate_refs.extend(inline_crate_refs);
                } else {
                    res.test_crate_refs.extend(inline_crate_refs);
                }

                let dup_idx = seen_fn_names.entry(fn_name.clone()).or_insert(0);
                let qual_name = if *dup_idx == 0 {
                    format!("{}::{}", rel_path, fn_name)
                } else {
                    format!("{}::{}#{}", rel_path, fn_name, *dup_idx)
                };
                *dup_idx += 1;

                res.functions.push(ParsedFunction {
                    rel_path: rel_path.to_string(),
                    fn_name,
                    qual_name,
                    start_line,
                    end_line,
                    is_test_scope: fn_is_test,
                    is_entrypoint: fn_is_entrypoint,
                    intra_calls,
                    ext_calls,
                });

                i = k + 1;
                continue;
            }

            TokenKind::LBrace => {
                brace_test_stack.push(in_test_scope);
                pending_pub = false;
                i += 1;
            }
            TokenKind::RBrace => {
                if brace_test_stack.len() > 1 {
                    brace_test_stack.pop();
                }
                pending_pub = false;
                pending_test_attr = false;
                pending_entrypoint_attr = false;
                i += 1;
            }
            TokenKind::Semi => {
                pending_pub = false;
                pending_test_attr = false;
                pending_entrypoint_attr = false;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    res
}

/// Parses a `use ...;` token slice into root crate names and `(local_symbol, root_crate)` pairs.
fn extract_use_bindings(slice: &[Token]) -> (BTreeSet<String>, Vec<(String, String)>) {
    let mut crates = BTreeSet::new();
    let mut pairs = Vec::new();
    if slice.is_empty() {
        return (crates, pairs);
    }

    // Root crate identifier is first identifier unless it is crate/self/super
    let first_ident = match &slice[0].kind {
        TokenKind::Ident(w) => w.clone(),
        TokenKind::ColonColon if slice.len() > 1 => match &slice[1].kind {
            TokenKind::Ident(w) => w.clone(),
            _ => return (crates, pairs),
        },
        _ => return (crates, pairs),
    };

    if matches!(
        first_ident.as_str(),
        "crate" | "self" | "super" | "std" | "core" | "alloc"
    ) {
        return (crates, pairs);
    }

    crates.insert(first_ident.clone());

    // Collect terminal identifiers or `orig as alias` bindings
    let mut i = 0usize;
    while i < slice.len() {
        if let TokenKind::Ident(w) = &slice[i].kind {
            // If followed by `as alias`, bind alias -> first_ident
            if i + 2 < slice.len() && matches!(&slice[i + 1].kind, TokenKind::Ident(a) if a == "as")
            {
                if let TokenKind::Ident(alias) = &slice[i + 2].kind {
                    pairs.push((alias.clone(), first_ident.clone()));
                }
                i += 3;
                continue;
            }
            // If terminal in path before `,`, `}`, or end of slice (e.g. `use chrono::{DateTime, NaiveDate}`)
            let is_terminal = i + 1 >= slice.len()
                || matches!(
                    slice[i + 1].kind,
                    TokenKind::Comma | TokenKind::RBrace | TokenKind::Semi
                );
            if is_terminal && w != "self" && w != "*" {
                pairs.push((w.clone(), first_ident.clone()));
            }
        }
        i += 1;
    }

    (crates, pairs)
}

/// Scans a function body for intra-crate function calls and external crate usage.
fn scan_function_body(
    body: &[Token],
    known_dep_idents: &BTreeMap<String, BTreeSet<String>>,
    sym_to_crate: &BTreeMap<String, String>,
) -> (
    BTreeSet<String>,
    BTreeSet<(String, String)>,
    BTreeSet<String>,
) {
    let mut intra_calls = BTreeSet::new();
    let mut ext_calls = BTreeSet::new();
    let mut inline_crates = BTreeSet::new();
    let len = body.len();
    let mut i = 0usize;

    while i < len {
        // Look for `<ident>::...` qualified paths
        if let TokenKind::Ident(first) = &body[i].kind {
            if i + 2 < len && matches!(body[i + 1].kind, TokenKind::ColonColon) {
                let mut chain = vec![first.clone()];
                let mut j = i + 1;
                while j + 1 < len && matches!(body[j].kind, TokenKind::ColonColon) {
                    if let TokenKind::Ident(seg) = &body[j + 1].kind {
                        chain.push(seg.clone());
                        j += 2;
                    } else {
                        break;
                    }
                }

                let is_call_or_macro =
                    j < len && matches!(body[j].kind, TokenKind::LParen | TokenKind::Bang);

                if known_dep_idents.contains_key(first) {
                    inline_crates.insert(first.clone());
                    let display = chain.join("::");
                    ext_calls.insert((first.clone(), display));
                } else if let Some(root_crate) = sym_to_crate.get(first) {
                    inline_crates.insert(root_crate.clone());
                    let display = format!("{}::{}", root_crate, chain.join("::"));
                    ext_calls.insert((root_crate.clone(), display));
                } else if is_call_or_macro && !chain.is_empty() {
                    if let Some(last) = chain.last() {
                        if !is_rust_keyword(last) {
                            intra_calls.insert(last.clone());
                        }
                    }
                }

                i = j;
                continue;
            }

            // Look for direct unqualified call `sym(...)` or `sym!(...)`
            if i + 1 < len
                && matches!(body[i + 1].kind, TokenKind::LParen | TokenKind::Bang)
                && !is_rust_keyword(first)
            {
                if let Some(root_crate) = sym_to_crate.get(first) {
                    inline_crates.insert(root_crate.clone());
                    ext_calls.insert((root_crate.clone(), format!("{}::{}", root_crate, first)));
                } else {
                    // Skip method calls like `.foo(` preceded by `.`
                    let is_method_call = i > 0 && matches!(body[i - 1].kind, TokenKind::Other('.'));
                    if !is_method_call {
                        intra_calls.insert(first.clone());
                    }
                }
            }
        }
        i += 1;
    }

    (intra_calls, ext_calls, inline_crates)
}

fn is_rust_keyword(w: &str) -> bool {
    matches!(
        w,
        "if" | "else"
            | "match"
            | "for"
            | "while"
            | "loop"
            | "return"
            | "let"
            | "fn"
            | "struct"
            | "enum"
            | "impl"
            | "trait"
            | "pub"
            | "use"
            | "mod"
            | "crate"
            | "self"
            | "super"
            | "where"
            | "async"
            | "await"
            | "Some"
            | "None"
            | "Ok"
            | "Err"
            | "println"
            | "eprintln"
            | "format"
            | "vec"
            | "assert"
            | "assert_eq"
            | "assert_ne"
    )
}

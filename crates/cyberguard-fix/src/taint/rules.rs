use crate::models::{SanitizerKind, TaintSinkKind, TaintSourceKind};

pub struct TaintRule {
    pub name: &'static str,
    pub source_indicators: &'static [&'static str],
    pub sink_indicators: &'static [&'static str],
    pub sanitizer_indicators: &'static [&'static str],
    pub sink_kind: TaintSinkKind,
}

pub static SQL_INJECTION_RULE: TaintRule = TaintRule {
    name: "CG-SQLI-001",
    source_indicators: &[
        "request.args",
        "request.form",
        "request.values",
        "req.query",
        "req.body",
        "req.params",
        "r.URL.Query()",
        "r.FormValue",
        "Query(",
        "param",
        "id",
        "user",
    ],
    sink_indicators: &[
        "execute",
        "executemany",
        "query",
        "Query",
        "QueryRow",
        "Exec",
    ],
    sanitizer_indicators: &["%s", "?", "$1", "int(", "parseInt(", "strconv.Atoi("],
    sink_kind: TaintSinkKind::SqlExecution,
};

pub static COMMAND_INJECTION_RULE: TaintRule = TaintRule {
    name: "CG-CMDI-001",
    source_indicators: &[
        "request.", "req.", "argv", "Args", "param", "host", "target", "cmd",
    ],
    sink_indicators: &[
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "os.system",
        "child_process.exec",
        "exec.Command",
        "Command::new",
    ],
    sanitizer_indicators: &["shlex.quote", "shell=False", "execFile"],
    sink_kind: TaintSinkKind::CommandExecution,
};

pub static PATH_TRAVERSAL_RULE: TaintRule = TaintRule {
    name: "CG-PATH-001",
    source_indicators: &["request.", "req.", "file", "path", "filename"],
    sink_indicators: &[
        "open(",
        "fs.readFile",
        "os.Open",
        "os.ReadFile",
        "File::open",
    ],
    sanitizer_indicators: &[
        "os.path.basename",
        "filepath.Base",
        "filepath.Rel",
        "strings.HasPrefix",
        "path.resolve",
    ],
    sink_kind: TaintSinkKind::PathTraversal,
};

pub fn identify_taint_source(expr: &str) -> Option<(TaintSourceKind, String)> {
    let lower = expr.to_ascii_lowercase();
    if lower.contains("request.args") || lower.contains("req.query") || lower.contains("url.query")
    {
        Some((TaintSourceKind::HttpQueryParam, expr.to_string()))
    } else if lower.contains("request.json")
        || lower.contains("request.form")
        || lower.contains("req.body")
    {
        Some((TaintSourceKind::HttpRequestBody, expr.to_string()))
    } else if lower.contains("headers") || lower.contains("header") {
        Some((TaintSourceKind::HttpHeader, expr.to_string()))
    } else if lower.contains("argv")
        || lower.contains("os.args")
        || lower.contains("std::env::args")
    {
        Some((TaintSourceKind::CliArgument, expr.to_string()))
    } else if lower.contains("environ")
        || lower.contains("env[")
        || lower.contains("getenv")
        || lower.contains("std::env::var")
    {
        Some((TaintSourceKind::EnvironmentVariable, expr.to_string()))
    } else {
        None
    }
}

pub fn check_sanitizer(expr: &str, sink_kind: TaintSinkKind) -> Option<SanitizerKind> {
    match sink_kind {
        TaintSinkKind::SqlExecution => {
            if expr.contains("%s") || expr.contains('?') || expr.contains("$1") {
                Some(SanitizerKind::ParameterizedQuery)
            } else if expr.contains("int(") || expr.contains("parseInt(") || expr.contains("Atoi(")
            {
                Some(SanitizerKind::TypeCastIntegerOrBool)
            } else {
                None
            }
        }
        TaintSinkKind::CommandExecution => {
            if expr.contains("shlex.quote")
                || expr.contains("shell=False")
                || expr.contains("execFile")
            {
                Some(SanitizerKind::ShellQuoteOrArgArray)
            } else {
                None
            }
        }
        TaintSinkKind::PathTraversal => {
            if expr.contains("basename")
                || expr.contains("HasPrefix")
                || expr.contains("filepath.Rel")
            {
                Some(SanitizerKind::PathContainmentGuard)
            } else {
                None
            }
        }
        TaintSinkKind::HardcodedSecret => {
            if expr.contains("os.environ")
                || expr.contains("process.env")
                || expr.contains("os.Getenv")
                || expr.contains("std::env::var")
            {
                Some(SanitizerKind::EnvironmentLookup)
            } else {
                None
            }
        }
    }
}

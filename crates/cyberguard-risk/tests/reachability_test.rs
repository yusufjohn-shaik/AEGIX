use cyberguard_risk::{
    CargoDependencyGraphBuilder, DependencyGraphBuilder, DependencyScope, MetadataSource,
    ReachabilityAnalyzer, ReachabilityStatus, RustCallGraphAnalyzer,
};
use std::path::PathBuf;

fn temp_workspace_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aegix-risk-{}-{}", name, nanos));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    dir
}

#[test]
fn test_parse_cargo_metadata_json_with_renames_and_scopes() {
    let sample = serde_json::json!({
        "workspace_root": "/tmp/ws",
        "workspace_members": ["app 0.1.0 (path+file:///tmp/ws)"],
        "packages": [
            {
                "id": "app 0.1.0 (path+file:///tmp/ws)",
                "name": "app",
                "version": "0.1.0",
                "manifest_path": "/tmp/ws/Cargo.toml",
                "targets": [
                    { "kind": ["bin"], "src_path": "/tmp/ws/src/main.rs" }
                ]
            },
            {
                "id": "chrono 0.4.19",
                "name": "chrono",
                "version": "0.4.19",
                "manifest_path": "/cargo/chrono/Cargo.toml",
                "targets": [{ "kind": ["lib"], "src_path": "/cargo/chrono/src/lib.rs" }]
            },
            {
                "id": "cc 1.0.0",
                "name": "cc",
                "version": "1.0.0",
                "manifest_path": "/cargo/cc/Cargo.toml",
                "targets": [{ "kind": ["lib"], "src_path": "/cargo/cc/src/lib.rs" }]
            },
            {
                "id": "mockito 1.0.0",
                "name": "mockito",
                "version": "1.0.0",
                "manifest_path": "/cargo/mockito/Cargo.toml",
                "targets": [{ "kind": ["lib"], "src_path": "/cargo/mockito/src/lib.rs" }]
            },
            {
                "id": "orphan-crate 0.2.0",
                "name": "orphan-crate",
                "version": "0.2.0",
                "manifest_path": "/cargo/orphan/Cargo.toml",
                "targets": [{ "kind": ["lib"], "src_path": "/cargo/orphan/src/lib.rs" }]
            }
        ],
        "resolve": {
            "nodes": [
                {
                    "id": "app 0.1.0 (path+file:///tmp/ws)",
                    "deps": [
                        {
                            "name": "my_chrono_alias",
                            "pkg": "chrono 0.4.19",
                            "dep_kinds": [{ "kind": null }]
                        },
                        {
                            "name": "cc",
                            "pkg": "cc 1.0.0",
                            "dep_kinds": [{ "kind": "build" }]
                        },
                        {
                            "name": "mockito",
                            "pkg": "mockito 1.0.0",
                            "dep_kinds": [{ "kind": "dev" }]
                        }
                    ]
                }
            ]
        }
    });

    let graph = CargoDependencyGraphBuilder::parse_cargo_metadata_json(
        &sample.to_string(),
        &PathBuf::from("/tmp/ws"),
    )
    .expect("metadata json parses");

    assert_eq!(graph.metadata_source, Some(MetadataSource::CargoMetadata));
    let chrono = graph.packages.get("chrono").unwrap();
    assert_eq!(chrono.scope, DependencyScope::NormalDirect);
    assert!(chrono.import_idents.contains("my_chrono_alias"));
    assert!(chrono.import_idents.contains("chrono"));

    assert_eq!(
        graph.packages.get("cc").unwrap().scope,
        DependencyScope::BuildDirect
    );
    assert_eq!(
        graph.packages.get("mockito").unwrap().scope,
        DependencyScope::DevDirect
    );
    assert_eq!(
        graph.packages.get("orphan-crate").unwrap().scope,
        DependencyScope::Orphaned
    );
}

#[tokio::test]
async fn test_rust_call_graph_reachability_and_cfg_test_isolation() {
    let dir = temp_workspace_dir("callgraph");

    let cargo_toml = r#"
[package]
name = "demo-service"
version = "0.1.0"
edition = "2021"

[dependencies]
chrono = "0.4.19"
regex = "1.10"
serde = "1.0"

[build-dependencies]
cc = "1.0"

[dev-dependencies]
mockito = "1.2"
"#;

    let cargo_lock = r#"
version = 3

[[package]]
name = "demo-service"
version = "0.1.0"
dependencies = [
 "chrono",
 "regex",
 "serde",
 "cc",
 "mockito",
]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "time",
]

[[package]]
name = "time"
version = "0.1.45"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "regex"
version = "1.10.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "cc"
version = "1.0.90"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "mockito"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "orphaned-pkg"
version = "0.9.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    let main_rs = r#"
use chrono::NaiveDate;
use regex;

// Mention in comment should not trigger usage: orphaned_pkg::evil()
/* Nested /* block comment with time::now() */ */

fn main() {
    let _msg = "orphaned_pkg::bad() string literal";
    let _parsed = parse_user_date("2026-11-26");
}

fn parse_user_date<'a>(input: &'a str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d").ok()
}

fn dead_unused_helper() {
    let _ch = 'x';
}

#[cfg(test)]
mod tests {
    use mockito;

    #[test]
    fn test_mock() {
        let _s = mockito::Server::new();
    }
}
"#;

    std::fs::write(dir.join("Cargo.toml"), cargo_toml).unwrap();
    std::fs::write(dir.join("Cargo.lock"), cargo_lock).unwrap();
    std::fs::write(dir.join("src").join("main.rs"), main_rs).unwrap();

    let builder = CargoDependencyGraphBuilder::new();
    let dep_graph = builder
        .build(&dir, false)
        .await
        .expect("pure-Rust fallback builds cleanly");

    assert_eq!(
        dep_graph.metadata_source,
        Some(MetadataSource::PureRustFallback)
    );

    let analyzer = RustCallGraphAnalyzer::new();
    let index = analyzer
        .analyze(&dep_graph, &dir)
        .expect("call graph analysis completes");

    // 1. chrono is invoked via main -> parse_user_date -> chrono::NaiveDate::parse_from_str
    let (chrono_status, chrono_trace, _) = index.crate_reachability.get("chrono").unwrap();
    assert_eq!(*chrono_status, ReachabilityStatus::VerifiedReachable);
    assert_eq!(
        chrono_trace,
        &vec![
            "src/main.rs::main".to_string(),
            "src/main.rs::parse_user_date".to_string(),
            "chrono::NaiveDate::parse_from_str".to_string(),
        ]
    );

    // 2. regex is imported in production source (`use regex;`)
    assert_eq!(
        index.crate_reachability.get("regex").unwrap().0,
        ReachabilityStatus::ImportedInSource
    );

    // 3. serde is declared in [dependencies] without src/ token match -> DirectDeclared (not Unreachable!)
    assert_eq!(
        index.crate_reachability.get("serde").unwrap().0,
        ReachabilityStatus::DirectDeclared
    );

    // 4. cc is [build-dependencies] -> BuildDependency (0.60, not DevOrTestOnly!)
    assert_eq!(
        index.crate_reachability.get("cc").unwrap().0,
        ReachabilityStatus::BuildDependency
    );

    // 5. time is transitive under chrono -> TransitiveReachable
    assert_eq!(
        index.crate_reachability.get("time").unwrap().0,
        ReachabilityStatus::TransitiveReachable
    );

    // 6. mockito is in [dev-dependencies] AND only used inside #[cfg(test)] mod tests -> DevOrTestOnly
    assert_eq!(
        index.crate_reachability.get("mockito").unwrap().0,
        ReachabilityStatus::DevOrTestOnly
    );

    // 7. orphaned-pkg has no edges and only appears in comment/string -> Unreachable (0.00)
    assert_eq!(
        index.crate_reachability.get("orphaned-pkg").unwrap().0,
        ReachabilityStatus::Unreachable
    );

    // 8. Check line-level function spans for SAST integration
    let spans = index.function_spans.get("src/main.rs").unwrap();
    let parse_span = spans
        .iter()
        .find(|s| s.qual_name == "src/main.rs::parse_user_date")
        .unwrap();
    assert!(parse_span.entrypoint_trace.is_some());
    assert!(!parse_span.is_test_scope);

    let dead_span = spans
        .iter()
        .find(|s| s.qual_name == "src/main.rs::dead_unused_helper")
        .unwrap();
    assert!(dead_span.entrypoint_trace.is_none());

    let test_span = spans
        .iter()
        .find(|s| s.qual_name == "src/main.rs::test_mock")
        .unwrap();
    assert!(test_span.is_test_scope);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_untrusted_cargo_config_blocks_subprocess_execution() {
    let dir = temp_workspace_dir("untrusted-cfg");
    std::fs::create_dir_all(dir.join(".cargo")).unwrap();
    std::fs::write(
        dir.join(".cargo").join("config.toml"),
        "[build]\nrustc-wrapper = \"/tmp/evil.sh\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}").unwrap();

    let builder = CargoDependencyGraphBuilder::new();
    let graph = builder.build(&dir, true).await.expect("falls back cleanly");

    assert_eq!(
        graph.metadata_source,
        Some(MetadataSource::PureRustFallback)
    );
    assert!(graph
        .warnings
        .iter()
        .any(|w| w.contains("untrusted overrides")));

    let _ = std::fs::remove_dir_all(&dir);
}

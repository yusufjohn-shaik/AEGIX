//! Hardened Cargo workspace dependency graph builder (`cargo metadata` + pure-Rust fallback).

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{
    DependencyNode, DependencyScope, MetadataSource, WorkspaceDependencyGraph, WorkspaceTargetRoot,
};
use crate::traits::DependencyGraphBuilder;
use async_trait::async_trait;
use cyberguard_proc::{execute_process, ProcessOptions};
use cyberguard_sca::parsers::CargoLockParser;
use cyberguard_sca::traits::LockfileParser;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

const CARGO_METADATA_TIMEOUT_SECS: u64 = 30;
const CARGO_METADATA_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Default, Clone)]
pub struct CargoDependencyGraphBuilder;

impl CargoDependencyGraphBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Normalizes a Cargo crate name into its Rust identifier form (`-` -> `_`).
    pub fn normalize_ident(name: &str) -> String {
        name.trim().replace('-', "_")
    }

    /// Locates the workspace/crate root containing `Cargo.toml` or `Cargo.lock`.
    pub fn locate_manifest_root(target: &Path) -> Option<PathBuf> {
        let start_dir = if target.is_file() {
            target.parent()?
        } else {
            target
        };

        let mut curr = Some(start_dir);
        for _ in 0..5 {
            if let Some(dir) = curr {
                if dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file() {
                    return Some(dir.to_path_buf());
                }
                curr = dir.parent();
            } else {
                break;
            }
        }
        None
    }

    /// Checks whether `.cargo/config.toml` or `.cargo/config` contains dangerous host-RCE overrides.
    fn has_untrusted_cargo_config(root: &Path) -> Option<String> {
        let candidates = [
            root.join(".cargo").join("config.toml"),
            root.join(".cargo").join("config"),
        ];
        for path in candidates {
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let lower = content.to_lowercase();
                    if lower.contains("rustc-wrapper")
                        || lower.contains("rustc-workspace-wrapper")
                        || lower.contains("rustc =")
                        || lower.contains("rustc=")
                        || lower.contains("[env]")
                    {
                        return Some(format!(
                            "Skipped `cargo metadata` due to untrusted overrides in {}",
                            path.display()
                        ));
                    }
                }
            }
        }
        None
    }

    /// Parses raw `cargo metadata --format-version 1` JSON cleanly into `WorkspaceDependencyGraph`.
    pub fn parse_cargo_metadata_json(
        json_str: &str,
        fallback_root: &Path,
    ) -> Result<WorkspaceDependencyGraph, RiskError> {
        let raw: RawCargoMetadata = serde_json::from_str(json_str)
            .map_err(|e| RiskError::CargoMetadataFailed(format!("Invalid metadata JSON: {}", e)))?;

        let workspace_root = raw
            .workspace_root
            .unwrap_or_else(|| fallback_root.to_path_buf());

        let member_ids: BTreeSet<String> = raw.workspace_members.iter().cloned().collect();
        let mut pkg_by_id: BTreeMap<String, RawMetadataPackage> = BTreeMap::new();
        for p in raw.packages {
            pkg_by_id.insert(p.id.clone(), p);
        }

        let mut target_roots = Vec::new();
        for member_id in &member_ids {
            if let Some(pkg) = pkg_by_id.get(member_id) {
                let manifest_dir = pkg
                    .manifest_path
                    .parent()
                    .unwrap_or(&workspace_root)
                    .to_path_buf();
                let crate_ident = Self::normalize_ident(&pkg.name);

                for t in &pkg.targets {
                    let is_library = t.kind.iter().any(|k| {
                        matches!(
                            k.as_str(),
                            "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                        )
                    });
                    let is_proc_macro = t.kind.iter().any(|k| k == "proc-macro");
                    let is_bin = t.kind.iter().any(|k| k == "bin");

                    if is_library || is_bin {
                        target_roots.push(WorkspaceTargetRoot {
                            crate_name: pkg.name.clone(),
                            crate_ident: crate_ident.clone(),
                            is_library,
                            is_proc_macro,
                            src_path: t.src_path.clone(),
                            manifest_dir: manifest_dir.clone(),
                        });
                    }
                }
            }
        }

        // Compute best dependency scope per package ID from workspace members over resolve graph
        let mut best_scope_by_id: BTreeMap<String, DependencyScope> = BTreeMap::new();
        let mut idents_by_id: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut parents_by_id: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        if let Some(resolve) = raw.resolve {
            let mut node_map: BTreeMap<String, RawResolveNode> = BTreeMap::new();
            for n in resolve.nodes {
                node_map.insert(n.id.clone(), n);
            }

            // BFS state: (package_id, inherited_scope, depth_from_workspace_member)
            let mut queue: VecDeque<(String, DependencyScope, usize)> = VecDeque::new();
            for m_id in &member_ids {
                best_scope_by_id.insert(m_id.clone(), DependencyScope::NormalDirect);
                queue.push_back((m_id.clone(), DependencyScope::NormalDirect, 0));
            }

            while let Some((curr_id, parent_scope, depth)) = queue.pop_front() {
                let curr_name = pkg_by_id
                    .get(&curr_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| curr_id.clone());

                if let Some(node) = node_map.get(&curr_id) {
                    for dep in &node.deps {
                        let dep_ident = Self::normalize_ident(&dep.name);
                        idents_by_id
                            .entry(dep.pkg.clone())
                            .or_default()
                            .insert(dep_ident);
                        parents_by_id
                            .entry(dep.pkg.clone())
                            .or_default()
                            .insert(curr_name.clone());

                        // Determine edge kind(s) declared on this dependency link
                        let edge_scopes = classify_resolve_dep_kinds(&dep.dep_kinds);
                        for edge_kind in edge_scopes {
                            let derived_scope = if depth == 0 {
                                match edge_kind {
                                    EdgeKind::Normal => DependencyScope::NormalDirect,
                                    EdgeKind::Build => DependencyScope::BuildDirect,
                                    EdgeKind::Dev => DependencyScope::DevDirect,
                                }
                            } else {
                                combine_transitive_scope(parent_scope, edge_kind)
                            };

                            let should_update = match best_scope_by_id.get(&dep.pkg) {
                                Some(existing) => derived_scope < *existing,
                                None => true,
                            };

                            if should_update {
                                best_scope_by_id.insert(dep.pkg.clone(), derived_scope);
                                queue.push_back((dep.pkg.clone(), derived_scope, depth + 1));
                            }
                        }
                    }
                }
            }
        }

        let mut packages = BTreeMap::new();
        for (pkg_id, raw_pkg) in pkg_by_id {
            let norm_ident = Self::normalize_ident(&raw_pkg.name);
            let mut import_idents = idents_by_id.remove(&pkg_id).unwrap_or_default();
            import_idents.insert(norm_ident.clone());

            let is_member = member_ids.contains(&pkg_id);
            let is_proc_macro = raw_pkg
                .targets
                .iter()
                .any(|t| t.kind.iter().any(|k| k == "proc-macro"));

            let scope = if is_member {
                DependencyScope::NormalDirect
            } else {
                best_scope_by_id
                    .get(&pkg_id)
                    .copied()
                    .unwrap_or(DependencyScope::Orphaned)
            };

            let dep_node = DependencyNode {
                name: raw_pkg.name.clone(),
                normalized_ident: norm_ident,
                version: raw_pkg.version,
                is_workspace_member: is_member,
                is_proc_macro,
                scope,
                import_idents,
                depended_by: parents_by_id.remove(&pkg_id).unwrap_or_default(),
            };

            packages.insert(raw_pkg.name, dep_node);
        }

        Ok(WorkspaceDependencyGraph {
            workspace_root,
            metadata_source: Some(MetadataSource::CargoMetadata),
            warnings: Vec::new(),
            target_roots,
            packages,
        })
    }

    /// Pure-Rust offline manifest & lockfile fallback parser (handles workspace globs, renames, normal/dev/build).
    pub fn build_pure_rust_fallback(root: &Path) -> Result<WorkspaceDependencyGraph, RiskError> {
        let mut graph = WorkspaceDependencyGraph {
            workspace_root: root.to_path_buf(),
            metadata_source: Some(MetadataSource::PureRustFallback),
            warnings: Vec::new(),
            target_roots: Vec::new(),
            packages: BTreeMap::new(),
        };

        // 1. Collect all workspace member Cargo.toml manifests
        let root_manifest = root.join("Cargo.toml");
        let mut member_dirs: Vec<PathBuf> = Vec::new();
        let mut workspace_dep_aliases: BTreeMap<String, String> = BTreeMap::new();

        if root_manifest.is_file() {
            let content = std::fs::read_to_string(&root_manifest)?;
            let parsed: toml::Value = toml::from_str(&content)?;

            if parsed.get("package").is_some() {
                member_dirs.push(root.to_path_buf());
            }

            if let Some(ws) = parsed.get("workspace").and_then(|v| v.as_table()) {
                if let Some(ws_deps) = ws.get("dependencies").and_then(|v| v.as_table()) {
                    for (alias, spec) in ws_deps {
                        let actual = spec
                            .as_table()
                            .and_then(|t| t.get("package"))
                            .and_then(|p| p.as_str())
                            .unwrap_or(alias.as_str());
                        workspace_dep_aliases.insert(alias.clone(), actual.to_string());
                    }
                }

                if let Some(members) = ws.get("members").and_then(|v| v.as_array()) {
                    for m in members {
                        if let Some(pattern) = m.as_str() {
                            expand_workspace_member_pattern(root, pattern, &mut member_dirs);
                        }
                    }
                }
            }
        }

        // Deduplicate member dirs deterministically
        let unique_members: BTreeSet<PathBuf> = member_dirs.into_iter().collect();

        // Direct dependency maps: pkg_name -> (DependencyScope, set of import_idents)
        let mut direct_edges: BTreeMap<String, (DependencyScope, BTreeSet<String>)> =
            BTreeMap::new();
        let mut member_names: BTreeSet<String> = BTreeSet::new();

        for dir in &unique_members {
            let manifest_path = dir.join("Cargo.toml");
            if !manifest_path.is_file() {
                continue;
            }
            let content = std::fs::read_to_string(&manifest_path)?;
            let parsed: toml::Value = toml::from_str(&content)?;

            let crate_name = parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or_else(|| {
                    dir.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("workspace-crate")
                })
                .to_string();
            let crate_version = parsed
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            let crate_ident = Self::normalize_ident(&crate_name);
            member_names.insert(crate_name.clone());

            let lib_is_proc_macro = parsed
                .get("lib")
                .and_then(|l| l.get("proc-macro"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false);

            // Identify source target roots (lib/main/bins)
            let lib_path = parsed
                .get("lib")
                .and_then(|l| l.get("path"))
                .and_then(|p| p.as_str())
                .map(|p| dir.join(p))
                .unwrap_or_else(|| dir.join("src").join("lib.rs"));
            if lib_path.is_file() {
                graph.target_roots.push(WorkspaceTargetRoot {
                    crate_name: crate_name.clone(),
                    crate_ident: crate_ident.clone(),
                    is_library: true,
                    is_proc_macro: lib_is_proc_macro,
                    src_path: lib_path,
                    manifest_dir: dir.clone(),
                });
            }

            let main_path = dir.join("src").join("main.rs");
            if main_path.is_file() {
                graph.target_roots.push(WorkspaceTargetRoot {
                    crate_name: crate_name.clone(),
                    crate_ident: crate_ident.clone(),
                    is_library: false,
                    is_proc_macro: false,
                    src_path: main_path,
                    manifest_dir: dir.clone(),
                });
            }

            if let Some(bins) = parsed.get("bin").and_then(|b| b.as_array()) {
                for bin in bins {
                    if let Some(p) = bin.get("path").and_then(|v| v.as_str()) {
                        let bp = dir.join(p);
                        if bp.is_file() {
                            graph.target_roots.push(WorkspaceTargetRoot {
                                crate_name: crate_name.clone(),
                                crate_ident: crate_ident.clone(),
                                is_library: false,
                                is_proc_macro: false,
                                src_path: bp,
                                manifest_dir: dir.clone(),
                            });
                        }
                    }
                }
            }

            // Ensure workspace member itself exists as a node
            let mut m_idents = BTreeSet::new();
            m_idents.insert(crate_ident.clone());
            graph.packages.insert(
                crate_name.clone(),
                DependencyNode {
                    name: crate_name.clone(),
                    normalized_ident: crate_ident,
                    version: crate_version,
                    is_workspace_member: true,
                    is_proc_macro: lib_is_proc_macro,
                    scope: DependencyScope::NormalDirect,
                    import_idents: m_idents,
                    depended_by: BTreeSet::new(),
                },
            );

            // Parse direct dependencies with section priority
            collect_manifest_deps(
                parsed.get("dependencies"),
                DependencyScope::NormalDirect,
                &workspace_dep_aliases,
                &mut direct_edges,
            );
            collect_manifest_deps(
                parsed.get("build-dependencies"),
                DependencyScope::BuildDirect,
                &workspace_dep_aliases,
                &mut direct_edges,
            );
            collect_manifest_deps(
                parsed.get("dev-dependencies"),
                DependencyScope::DevDirect,
                &workspace_dep_aliases,
                &mut direct_edges,
            );
        }

        // 2. Parse Cargo.lock via cyberguard-sca::CargoLockParser for transitive graph edges
        let lock_path = root.join("Cargo.lock");
        let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut parents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        if lock_path.is_file() {
            let lock_content = std::fs::read_to_string(&lock_path)?;
            let parser = CargoLockParser::new();
            if let Ok(pkgs) = parser.parse(&lock_path, &lock_content) {
                for pkg in pkgs {
                    adjacency.insert(pkg.name.clone(), pkg.dependencies.clone());
                    for dep in &pkg.dependencies {
                        parents
                            .entry(dep.clone())
                            .or_default()
                            .insert(pkg.name.clone());
                    }

                    let entry = graph.packages.entry(pkg.name.clone()).or_insert_with(|| {
                        let norm = Self::normalize_ident(&pkg.name);
                        let mut idents = BTreeSet::new();
                        idents.insert(norm.clone());
                        DependencyNode {
                            name: pkg.name.clone(),
                            normalized_ident: norm,
                            version: pkg.version.clone(),
                            is_workspace_member: member_names.contains(&pkg.name),
                            is_proc_macro: false,
                            scope: DependencyScope::Orphaned,
                            import_idents: idents,
                            depended_by: BTreeSet::new(),
                        }
                    });
                    if entry.version == "0.0.0" {
                        entry.version = pkg.version;
                    }
                }
            }
        }

        // Seed nodes for direct deps declared in Cargo.toml even if Cargo.lock was absent
        for (pkg_name, (scope, idents)) in &direct_edges {
            let entry = graph.packages.entry(pkg_name.clone()).or_insert_with(|| {
                let norm = Self::normalize_ident(pkg_name);
                DependencyNode {
                    name: pkg_name.clone(),
                    normalized_ident: norm,
                    version: "unknown".to_string(),
                    is_workspace_member: member_names.contains(pkg_name),
                    is_proc_macro: false,
                    scope: *scope,
                    import_idents: BTreeSet::new(),
                    depended_by: BTreeSet::new(),
                }
            });
            entry.import_idents.extend(idents.iter().cloned());
            if *scope < entry.scope {
                entry.scope = *scope;
            }
        }

        // BFS from direct dependencies to propagate transitive scopes accurately
        let mut best_scope: BTreeMap<String, DependencyScope> = BTreeMap::new();
        let mut queue: VecDeque<(String, DependencyScope)> = VecDeque::new();

        for (pkg_name, (scope, _)) in &direct_edges {
            best_scope.insert(pkg_name.clone(), *scope);
            queue.push_back((pkg_name.clone(), *scope));
        }

        while let Some((curr_pkg, curr_scope)) = queue.pop_front() {
            if let Some(children) = adjacency.get(&curr_pkg) {
                let child_scope = match curr_scope {
                    DependencyScope::NormalDirect | DependencyScope::NormalTransitive => {
                        DependencyScope::NormalTransitive
                    }
                    DependencyScope::BuildDirect | DependencyScope::BuildTransitive => {
                        DependencyScope::BuildTransitive
                    }
                    _ => DependencyScope::DevTransitive,
                };
                for child in children {
                    let should_update = match best_scope.get(child) {
                        Some(existing) => child_scope < *existing,
                        None => true,
                    };
                    if should_update {
                        best_scope.insert(child.clone(), child_scope);
                        queue.push_back((child.clone(), child_scope));
                    }
                }
            }
        }

        for (name, node) in &mut graph.packages {
            if node.is_workspace_member {
                node.scope = DependencyScope::NormalDirect;
            } else if let Some(scope) = best_scope.get(name) {
                node.scope = *scope;
            }
            if let Some(ps) = parents.get(name) {
                node.depended_by = ps.clone();
            }
        }

        Ok(graph)
    }
}

#[async_trait]
impl DependencyGraphBuilder for CargoDependencyGraphBuilder {
    async fn build(
        &self,
        target: &Path,
        use_cargo_metadata: bool,
    ) -> Result<WorkspaceDependencyGraph, RiskError> {
        let Some(root) = Self::locate_manifest_root(target) else {
            return Ok(WorkspaceDependencyGraph {
                workspace_root: target.to_path_buf(),
                metadata_source: Some(MetadataSource::NotApplicable),
                ..Default::default()
            });
        };

        let manifest_path = root.join("Cargo.toml");
        let mut warnings = Vec::new();

        if use_cargo_metadata && manifest_path.is_file() {
            if let Some(warn) = Self::has_untrusted_cargo_config(&root) {
                warnings.push(warn);
            } else {
                let canonical_manifest =
                    std::fs::canonicalize(&manifest_path).unwrap_or_else(|_| manifest_path.clone());
                let manifest_arg = canonical_manifest.to_string_lossy().to_string();

                let args = vec![
                    "metadata".to_string(),
                    "--format-version".to_string(),
                    "1".to_string(),
                    "--offline".to_string(),
                    "--locked".to_string(),
                    "--manifest-path".to_string(),
                    manifest_arg,
                ];

                let options = ProcessOptions::new("cargo", args)
                    .with_current_dir(root.clone())
                    .with_timeout(Duration::from_secs(CARGO_METADATA_TIMEOUT_SECS))
                    .with_max_output(CARGO_METADATA_MAX_BYTES)
                    .with_env("RUSTC_WRAPPER", "")
                    .with_env("RUSTC_WORKSPACE_WRAPPER", "")
                    .with_env("CARGO_BUILD_RUSTC_WRAPPER", "")
                    .with_env("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "")
                    .with_env("RUSTFLAGS", "")
                    .with_env("CARGO_ENCODED_RUSTFLAGS", "")
                    .with_env("CARGO_NET_OFFLINE", "true");

                match execute_process(options).await {
                    Ok(output) if output.is_success() && !output.truncated => {
                        match Self::parse_cargo_metadata_json(&output.stdout, &root) {
                            Ok(mut graph) => {
                                graph.warnings.extend(warnings);
                                return Ok(graph);
                            }
                            Err(e) => {
                                warnings.push(format!(
                                    "cargo metadata JSON parse failed ({}), falling back to Cargo.toml/Cargo.lock",
                                    e
                                ));
                            }
                        }
                    }
                    Ok(output) => {
                        let reason = if output.truncated {
                            "output exceeded 32 MiB limit".to_string()
                        } else {
                            format!(
                                "exit code {:?}: {}",
                                output.exit_code,
                                output.stderr.lines().next().unwrap_or("unknown error")
                            )
                        };
                        warnings.push(format!(
                            "cargo metadata --offline --locked did not complete ({}), using pure-Rust fallback",
                            reason
                        ));
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "cargo subprocess unavailable ({}), using pure-Rust fallback",
                            e
                        ));
                    }
                }
            }
        }

        let mut fallback = Self::build_pure_rust_fallback(&root)?;
        fallback.warnings.extend(warnings);
        Ok(fallback)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeKind {
    Normal,
    Build,
    Dev,
}

fn classify_resolve_dep_kinds(dep_kinds: &[RawDepKind]) -> Vec<EdgeKind> {
    if dep_kinds.is_empty() {
        return vec![EdgeKind::Normal];
    }
    let mut kinds = Vec::with_capacity(dep_kinds.len());
    for dk in dep_kinds {
        match dk.kind.as_deref() {
            Some("dev") => kinds.push(EdgeKind::Dev),
            Some("build") => kinds.push(EdgeKind::Build),
            _ => kinds.push(EdgeKind::Normal),
        }
    }
    kinds
}

fn combine_transitive_scope(parent: DependencyScope, edge: EdgeKind) -> DependencyScope {
    match (parent, edge) {
        (DependencyScope::NormalDirect | DependencyScope::NormalTransitive, EdgeKind::Normal) => {
            DependencyScope::NormalTransitive
        }
        (DependencyScope::NormalDirect | DependencyScope::NormalTransitive, EdgeKind::Build)
        | (DependencyScope::BuildDirect | DependencyScope::BuildTransitive, EdgeKind::Normal)
        | (DependencyScope::BuildDirect | DependencyScope::BuildTransitive, EdgeKind::Build) => {
            DependencyScope::BuildTransitive
        }
        _ => DependencyScope::DevTransitive,
    }
}

fn expand_workspace_member_pattern(root: &Path, pattern: &str, out: &mut Vec<PathBuf>) {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(prefix) = trimmed.strip_suffix("/*") {
        let parent = root.join(prefix);
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && p.join("Cargo.toml").is_file() {
                    out.push(p);
                }
            }
        }
    } else if !trimmed.contains('*') {
        let p = root.join(trimmed);
        if p.is_dir() && p.join("Cargo.toml").is_file() {
            out.push(p);
        }
    }
}

fn collect_manifest_deps(
    table_opt: Option<&toml::Value>,
    scope: DependencyScope,
    workspace_aliases: &BTreeMap<String, String>,
    out: &mut BTreeMap<String, (DependencyScope, BTreeSet<String>)>,
) {
    let Some(table) = table_opt.and_then(|v| v.as_table()) else {
        return;
    };

    for (alias, spec) in table {
        let actual_pkg = spec
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(|p| p.as_str())
            .map(str::to_string)
            .or_else(|| {
                let is_ws = spec
                    .as_table()
                    .and_then(|t| t.get("workspace"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                if is_ws {
                    workspace_aliases.get(alias).cloned()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| alias.clone());

        let alias_ident = CargoDependencyGraphBuilder::normalize_ident(alias);
        let actual_ident = CargoDependencyGraphBuilder::normalize_ident(&actual_pkg);

        let entry = out
            .entry(actual_pkg)
            .or_insert_with(|| (scope, BTreeSet::new()));
        if scope < entry.0 {
            entry.0 = scope;
        }
        entry.1.insert(alias_ident);
        entry.1.insert(actual_ident);
    }
}

// --- Raw `cargo metadata --format-version 1` Deserialization Structs ---

#[derive(Debug, Deserialize)]
struct RawCargoMetadata {
    #[serde(default)]
    packages: Vec<RawMetadataPackage>,
    #[serde(default)]
    workspace_members: Vec<String>,
    #[serde(default)]
    resolve: Option<RawMetadataResolve>,
    #[serde(default)]
    workspace_root: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataPackage {
    id: String,
    name: String,
    version: String,
    manifest_path: PathBuf,
    #[serde(default)]
    targets: Vec<RawMetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataTarget {
    #[serde(default)]
    kind: Vec<String>,
    src_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawMetadataResolve {
    #[serde(default)]
    nodes: Vec<RawResolveNode>,
}

#[derive(Debug, Deserialize)]
struct RawResolveNode {
    id: String,
    #[serde(default)]
    deps: Vec<RawResolveDep>,
}

#[derive(Debug, Deserialize)]
struct RawResolveDep {
    name: String,
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<RawDepKind>,
}

#[derive(Debug, Deserialize)]
struct RawDepKind {
    #[serde(default)]
    kind: Option<String>,
}

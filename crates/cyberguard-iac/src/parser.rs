use crate::error::IacError;
use crate::models::{
    IacDocument, IacFormat, IacResource, K8sManifest, TerraformLocal, TerraformResource,
    TerraformVariable,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MAX_IAC_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB ceiling
pub const MAX_DOCUMENTS_PER_FILE: usize = 500; // Document stream ceiling

pub struct IacParser;

impl IacParser {
    pub fn parse_file(path: &Path) -> Result<Vec<IacDocument>, IacError> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        if size > MAX_IAC_FILE_SIZE {
            return Err(IacError::FileSizeLimitExceeded {
                size,
                max_allowed: MAX_IAC_FILE_SIZE,
            });
        }

        let mut content = String::with_capacity(size);
        file.read_to_string(&mut content)?;
        Self::parse_str(&content, path)
    }

    pub fn parse_str(content: &str, path_hint: &Path) -> Result<Vec<IacDocument>, IacError> {
        let format = Self::detect_format(content, path_hint)?;
        match format {
            IacFormat::KubernetesYaml => Self::parse_k8s_yaml(content, path_hint),
            IacFormat::KubernetesJson => Self::parse_k8s_json(content, path_hint),
            IacFormat::TerraformHcl => Self::parse_terraform_hcl(content, path_hint),
            IacFormat::TerraformJson | IacFormat::TerraformPlanJson => {
                Self::parse_terraform_json(content, path_hint, format)
            }
        }
    }

    pub fn detect_format(content: &str, path_hint: &Path) -> Result<IacFormat, IacError> {
        let path_str = path_hint.to_string_lossy();
        if path_str.ends_with(".tf.json") {
            return Ok(IacFormat::TerraformJson);
        }

        let ext = path_hint
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if ext == "tf" {
            return Ok(IacFormat::TerraformHcl);
        }

        if ext == "json" {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                if val.get("apiVersion").is_some() && val.get("kind").is_some() {
                    return Ok(IacFormat::KubernetesJson);
                }
                if val.get("format_version").is_some() || val.get("planned_values").is_some() {
                    return Ok(IacFormat::TerraformPlanJson);
                }
                if val.get("resource").is_some() || val.get("variable").is_some() {
                    return Ok(IacFormat::TerraformJson);
                }
            }
            return Ok(IacFormat::KubernetesJson);
        }

        if ext == "yaml" || ext == "yml" {
            return Ok(IacFormat::KubernetesYaml);
        }

        // Fallback content heuristics
        if content.contains("apiVersion:") && content.contains("kind:") {
            return Ok(IacFormat::KubernetesYaml);
        }
        if content.contains("resource \"")
            || content.contains("variable \"")
            || content.contains("locals {")
        {
            return Ok(IacFormat::TerraformHcl);
        }

        Err(IacError::UnrecognizedFormat(
            path_hint.display().to_string(),
        ))
    }

    /// Stream-deserializes multi-document YAML manifests safely.
    fn parse_k8s_yaml(content: &str, path_hint: &Path) -> Result<Vec<IacDocument>, IacError> {
        let mut docs = Vec::new();
        let path_str = path_hint.display().to_string();

        for (idx, document) in serde_yaml::Deserializer::from_str(content).enumerate() {
            if idx >= MAX_DOCUMENTS_PER_FILE {
                return Err(IacError::DocumentCountExceeded {
                    count: idx + 1,
                    max_allowed: MAX_DOCUMENTS_PER_FILE,
                });
            }

            let val: serde_yaml::Value = match serde_yaml::Value::deserialize(document) {
                Ok(v) => v,
                Err(e) => {
                    // Gracefully skip unrendered Helm Go-template documents
                    if content.contains("{{") && content.contains("}}") {
                        tracing::debug!(
                            "Skipping unrendered Helm template document in {}",
                            path_str
                        );
                        continue;
                    }
                    return Err(IacError::YamlParse(e));
                }
            };

            if val.is_null() {
                continue;
            }

            let json_str = match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => {
                    if content.contains("{{") && content.contains("}}") {
                        tracing::debug!(
                            "Skipping unrendered Helm template document in {}",
                            path_str
                        );
                        continue;
                    }
                    return Err(IacError::JsonParse(e));
                }
            };
            if let Ok(manifest) = serde_json::from_str::<K8sManifest>(&json_str) {
                if !manifest.kind.is_empty() {
                    docs.push(IacDocument {
                        document_index: idx,
                        format: IacFormat::KubernetesYaml,
                        file_path: path_str.clone(),
                        resources: vec![IacResource::Kubernetes(Box::new(manifest))],
                        raw_content: content.to_string(),
                    });
                }
            }
        }

        Ok(docs)
    }

    fn parse_k8s_json(content: &str, path_hint: &Path) -> Result<Vec<IacDocument>, IacError> {
        let manifest: K8sManifest = serde_json::from_str(content)?;
        Ok(vec![IacDocument {
            document_index: 0,
            format: IacFormat::KubernetesJson,
            file_path: path_hint.display().to_string(),
            resources: vec![IacResource::Kubernetes(Box::new(manifest))],
            raw_content: content.to_string(),
        }])
    }

    /// Structural pure-Rust HCL Block and Attribute Parser.
    pub fn parse_terraform_hcl(
        content: &str,
        path_hint: &Path,
    ) -> Result<Vec<IacDocument>, IacError> {
        let mut resources = Vec::new();
        let mut variables = Vec::new();
        let mut locals = Vec::new();

        let lines: Vec<&str> = content.lines().collect();
        let mut line_idx = 0;

        while line_idx < lines.len() {
            let line = lines[line_idx].trim();

            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                line_idx += 1;
                continue;
            }

            // 1. Match resource blocks: resource "type" "name" {
            if line.starts_with("resource ") && line.ends_with('{') {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let r_type = parts[1].trim_matches('"').to_string();
                    let r_name = parts[2].trim_matches('"').to_string();
                    let start_line = line_idx + 1;

                    let (block_content, end_line) = Self::extract_braced_block(&lines, line_idx);
                    let properties = Self::parse_hcl_attributes(&block_content);

                    resources.push(IacResource::Terraform(Box::new(TerraformResource {
                        resource_type: r_type,
                        resource_name: r_name,
                        properties,
                        line_start: start_line,
                        line_end: end_line,
                    })));

                    line_idx = end_line;
                    continue;
                }
            }

            // 2. Match variable blocks: variable "name" {
            if line.starts_with("variable ") && line.ends_with('{') {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let v_name = parts[1].trim_matches('"').to_string();
                    let start_line = line_idx + 1;
                    let (block_content, end_line) = Self::extract_braced_block(&lines, line_idx);
                    let props = Self::parse_hcl_attributes(&block_content);

                    variables.push(IacResource::TerraformVariable(TerraformVariable {
                        name: v_name,
                        default_value: props.get("default").cloned(),
                        description: props
                            .get("description")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        sensitive: props.get("sensitive").and_then(|v| v.as_bool()),
                        line: start_line,
                    }));

                    line_idx = end_line;
                    continue;
                }
            }

            // 3. Match locals block: locals {
            if line.starts_with("locals") && line.ends_with('{') {
                let start_line = line_idx + 1;
                let (block_content, end_line) = Self::extract_braced_block(&lines, line_idx);
                let props = Self::parse_hcl_attributes(&block_content);

                for (k, v) in props {
                    locals.push(IacResource::TerraformLocal(TerraformLocal {
                        name: k,
                        value: v,
                        line: start_line,
                    }));
                }

                line_idx = end_line;
                continue;
            }

            line_idx += 1;
        }

        let mut all_resources = resources;
        all_resources.extend(variables);
        all_resources.extend(locals);

        Ok(vec![IacDocument {
            document_index: 0,
            format: IacFormat::TerraformHcl,
            file_path: path_hint.display().to_string(),
            resources: all_resources,
            raw_content: content.to_string(),
        }])
    }

    /// Extracts lines inside an open brace `{` until matching closing brace `}`.
    fn extract_braced_block(lines: &[&str], start_line_idx: usize) -> (Vec<String>, usize) {
        let mut depth = 0;
        let mut block_lines = Vec::new();
        let mut curr = start_line_idx;

        while curr < lines.len() {
            let line = lines[curr];
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                }
            }

            if curr > start_line_idx {
                block_lines.push(line.to_string());
            }

            if depth == 0 && curr >= start_line_idx {
                return (block_lines, curr + 1);
            }
            curr += 1;
        }

        (block_lines, curr)
    }

    /// Structural key-value and nested block extractor for HCL definitions.
    fn parse_hcl_attributes(lines: &[String]) -> HashMap<String, serde_json::Value> {
        let mut map = HashMap::new();
        let mut idx = 0;

        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                idx += 1;
                continue;
            }

            // Check for nested block: e.g. ingress { ... } or rule { ... }
            if trimmed.ends_with('{') && !trimmed.contains('=') {
                let block_name = trimmed.trim_end_matches('{').trim().to_string();
                let mut nested_lines = Vec::new();
                let mut depth = 1;
                idx += 1;

                while idx < lines.len() && depth > 0 {
                    let nline = lines[idx].as_str();
                    for ch in nline.chars() {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                        }
                    }
                    if depth > 0 {
                        nested_lines.push(nline.to_string());
                    }
                    idx += 1;
                }

                let nested_attrs = Self::parse_hcl_attributes(&nested_lines);
                let nested_json = serde_json::Value::Object(nested_attrs.into_iter().collect());

                // If block already exists (e.g. multiple ingress blocks), convert to array
                if let Some(existing) = map.remove(&block_name) {
                    match existing {
                        serde_json::Value::Array(mut arr) => {
                            arr.push(nested_json);
                            map.insert(block_name, serde_json::Value::Array(arr));
                        }
                        other => {
                            map.insert(
                                block_name,
                                serde_json::Value::Array(vec![other, nested_json]),
                            );
                        }
                    }
                } else {
                    map.insert(block_name, nested_json);
                }
                continue;
            }

            // Key-value attribute: key = value
            if let Some((key, val_str)) = trimmed.split_once('=') {
                let k = key.trim().to_string();
                let v_clean = val_str.trim().trim_matches('"');

                if v_clean == "true" {
                    map.insert(k, serde_json::Value::Bool(true));
                } else if v_clean == "false" {
                    map.insert(k, serde_json::Value::Bool(false));
                } else if let Ok(num) = v_clean.parse::<i64>() {
                    map.insert(k, serde_json::Value::Number(num.into()));
                } else if v_clean.starts_with('[') && v_clean.ends_with(']') {
                    let items: Vec<serde_json::Value> = v_clean[1..v_clean.len() - 1]
                        .split(',')
                        .map(|s| serde_json::Value::String(s.trim().trim_matches('"').to_string()))
                        .filter(|v| !v.as_str().unwrap_or("").is_empty())
                        .collect();
                    map.insert(k, serde_json::Value::Array(items));
                } else {
                    map.insert(k, serde_json::Value::String(v_clean.to_string()));
                }
            }
            idx += 1;
        }

        map
    }

    fn parse_terraform_json(
        content: &str,
        path_hint: &Path,
        format: IacFormat,
    ) -> Result<Vec<IacDocument>, IacError> {
        let val: serde_json::Value = serde_json::from_str(content)?;
        let mut resources = Vec::new();

        // Standard Terraform JSON syntax: { "resource": { "type": { "name": { ... } } } }
        if let Some(res_map) = val.get("resource").and_then(|r| r.as_object()) {
            for (r_type, names_val) in res_map {
                if let Some(names_map) = names_val.as_object() {
                    for (r_name, props_val) in names_map {
                        let props = props_val
                            .as_object()
                            .map(|m| m.clone().into_iter().collect())
                            .unwrap_or_default();
                        resources.push(IacResource::Terraform(Box::new(TerraformResource {
                            resource_type: r_type.clone(),
                            resource_name: r_name.clone(),
                            properties: props,
                            line_start: 1,
                            line_end: 1,
                        })));
                    }
                }
            }
        }

        // Terraform Plan JSON syntax: planned_values.root_module.resources or resource_changes
        if let Some(res_changes) = val.get("resource_changes").and_then(|r| r.as_array()) {
            for rc in res_changes {
                let actions = rc
                    .get("change")
                    .and_then(|c| c.get("actions"))
                    .and_then(|a| a.as_array());
                let is_delete = actions
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("delete")))
                    .unwrap_or(false);
                if is_delete {
                    continue;
                }

                let r_type = rc.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                let r_name = rc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let after_props = rc
                    .get("change")
                    .and_then(|c| c.get("after"))
                    .and_then(|a| a.as_object())
                    .map(|m| m.clone().into_iter().collect())
                    .unwrap_or_default();

                resources.push(IacResource::Terraform(Box::new(TerraformResource {
                    resource_type: r_type.to_string(),
                    resource_name: r_name.to_string(),
                    properties: after_props,
                    line_start: 1,
                    line_end: 1,
                })));
            }
        }

        Ok(vec![IacDocument {
            document_index: 0,
            format,
            file_path: path_hint.display().to_string(),
            resources,
            raw_content: content.to_string(),
        }])
    }

    /// Scans raw text to match token key and calculate 1-based line and column.
    pub fn calculate_line_hint(content: &str, token: &str) -> (usize, usize) {
        for (i, line) in content.lines().enumerate() {
            if let Some(col) = line.find(token) {
                return (i + 1, col + 1);
            }
        }
        (1, 1)
    }
}

//! Specification ingestion, format normalization, and cycle-safe reference resolution.

use crate::error::ApiError;
use crate::models::{
    ApiSpec, Operation, ParamLocation, Parameter, RequestBody, Response, SchemaNode,
    SecurityScheme, SpecVersion,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SPEC_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const MAX_REF_DEPTH: usize = 32;

/// Parse an OpenAPI 3.0, 3.1, or Swagger 2.0 specification from a file path.
pub fn parse_spec_file(path: impl AsRef<Path>) -> Result<ApiSpec, ApiError> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_SPEC_SIZE_BYTES {
        return Err(ApiError::InvalidSpec(format!(
            "Specification file size exceeds maximum limit of 10 MB: {} bytes",
            metadata.len()
        )));
    }

    let content = fs::read_to_string(path)?;
    let spec_dir = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    parse_spec_str(&content, Some(&spec_dir))
}

/// Parse an OpenAPI 3.0, 3.1, or Swagger 2.0 specification from a string slice.
pub fn parse_spec_str(content: &str, spec_dir: Option<&Path>) -> Result<ApiSpec, ApiError> {
    let root: Value = if let Ok(val) = serde_json::from_str::<Value>(content) {
        val
    } else {
        serde_yaml::from_str::<Value>(content)?
    };

    let version = detect_version(&root)?;
    let title = root
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or("Untitled API")
        .to_string();

    let spec_version = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0")
        .to_string();

    let servers = extract_servers(&root, version);
    let security_definitions = extract_security_definitions(&root, version);
    let global_security = extract_security_requirements(root.get("security"));

    let mut parser_ctx = ParserContext {
        root: &root,
        spec_dir: spec_dir.map(|p| p.to_path_buf()),
        total_nodes: 0,
        schema_cache: HashMap::new(),
    };

    let operations = extract_operations(&mut parser_ctx, version, &global_security)?;

    Ok(ApiSpec {
        version,
        title,
        spec_version,
        servers,
        operations,
        security_definitions,
    })
}

fn detect_version(root: &Value) -> Result<SpecVersion, ApiError> {
    if let Some(swagger) = root.get("swagger").and_then(|s| s.as_str()) {
        if swagger.starts_with("2.") {
            return Ok(SpecVersion::Swagger2);
        }
    }

    if let Some(openapi) = root.get("openapi").and_then(|o| o.as_str()) {
        if openapi.starts_with("3.0") {
            return Ok(SpecVersion::OpenApi30);
        } else if openapi.starts_with("3.1") {
            return Ok(SpecVersion::OpenApi31);
        }
    }

    Err(ApiError::UnsupportedVersion(
        "Missing or unsupported 'openapi' (3.0/3.1) or 'swagger' (2.0) version field".to_string(),
    ))
}

fn extract_servers(root: &Value, version: SpecVersion) -> Vec<String> {
    let mut servers = Vec::new();

    match version {
        SpecVersion::OpenApi30 | SpecVersion::OpenApi31 => {
            if let Some(servers_arr) = root.get("servers").and_then(|s| s.as_array()) {
                for s in servers_arr {
                    if let Some(url) = s.get("url").and_then(|u| u.as_str()) {
                        servers.push(url.to_string());
                    }
                }
            }
        }
        SpecVersion::Swagger2 => {
            let host = root.get("host").and_then(|h| h.as_str()).unwrap_or("");
            let base_path = root.get("basePath").and_then(|b| b.as_str()).unwrap_or("");
            let schemes = root
                .get("schemes")
                .and_then(|s| s.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec!["https".to_string()]);

            if !host.is_empty() {
                for scheme in schemes {
                    servers.push(format!("{}://{}{}", scheme, host, base_path));
                }
            }
        }
    }

    servers
}

fn extract_security_definitions(
    root: &Value,
    version: SpecVersion,
) -> HashMap<String, SecurityScheme> {
    let mut map = HashMap::new();

    let defs = match version {
        SpecVersion::OpenApi30 | SpecVersion::OpenApi31 => root
            .get("components")
            .and_then(|c| c.get("securitySchemes")),
        SpecVersion::Swagger2 => root.get("securityDefinitions"),
    };

    if let Some(defs_map) = defs.and_then(|d| d.as_object()) {
        for (name, val) in defs_map {
            let scheme_type = val
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_string();
            let sec_name = val
                .get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
            let location = val
                .get("in")
                .and_then(|i| i.as_str())
                .map(|s| s.to_string());
            let scheme = val
                .get("scheme")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            map.insert(
                name.clone(),
                SecurityScheme {
                    scheme_type,
                    name: sec_name,
                    location,
                    scheme,
                },
            );
        }
    }

    map
}

fn extract_security_requirements(val: Option<&Value>) -> Vec<HashMap<String, Vec<String>>> {
    let mut res = Vec::new();
    if let Some(arr) = val.and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(obj) = item.as_object() {
                let mut req = HashMap::new();
                for (k, v) in obj {
                    let scopes = v
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|s| s.as_str().map(|str_val| str_val.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    req.insert(k.clone(), scopes);
                }
                res.push(req);
            }
        }
    }
    res
}

struct ParserContext<'a> {
    root: &'a Value,
    spec_dir: Option<PathBuf>,
    total_nodes: usize,
    schema_cache: HashMap<String, Box<SchemaNode>>,
}

fn extract_operations(
    ctx: &mut ParserContext,
    version: SpecVersion,
    global_security: &[HashMap<String, Vec<String>>],
) -> Result<Vec<Operation>, ApiError> {
    let mut operations = Vec::new();

    let paths_obj = match ctx.root.get("paths").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return Ok(operations),
    };

    for (path_str, path_val) in paths_obj {
        let is_admin = is_admin_path(path_str);
        let is_public = is_public_path(path_str);

        // Path-level parameters
        let path_params = parse_parameters(ctx, path_val.get("parameters"), version)?;

        for method in &["get", "post", "put", "delete", "patch", "head", "options"] {
            if let Some(op_val) = path_val.get(*method) {
                let operation_id = op_val
                    .get("operationId")
                    .and_then(|o| o.as_str())
                    .map(|s| s.to_string());
                let summary = op_val
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());

                // Operation parameters
                let mut op_params = parse_parameters(ctx, op_val.get("parameters"), version)?;

                // Combine path params with op params (op params override path params by name+location)
                let mut combined_params = path_params.clone();
                for p in op_params.drain(..) {
                    if let Some(idx) = combined_params
                        .iter()
                        .position(|cp| cp.name == p.name && cp.location == p.location)
                    {
                        combined_params[idx] = p;
                    } else {
                        combined_params.push(p);
                    }
                }

                // Request body
                let request_body = match version {
                    SpecVersion::OpenApi30 | SpecVersion::OpenApi31 => {
                        parse_openapi_request_body(ctx, op_val.get("requestBody"))?
                    }
                    SpecVersion::Swagger2 => {
                        // In Swagger 2.0, body parameters have in: "body"
                        parse_swagger_body_parameter(ctx, op_val.get("parameters"))?
                    }
                };

                // Responses
                let responses = parse_responses(ctx, op_val.get("responses"), version)?;

                // Security: if op has explicit security field, use it (even if empty `[]`), else inherit global
                let security = if op_val.get("security").is_some() {
                    extract_security_requirements(op_val.get("security"))
                } else {
                    global_security.to_vec()
                };

                operations.push(Operation {
                    method: method.to_uppercase(),
                    path: path_str.clone(),
                    operation_id,
                    summary,
                    parameters: combined_params,
                    request_body,
                    responses,
                    security,
                    is_admin_route: is_admin,
                    is_public_exempt: is_public,
                });
            }
        }
    }

    Ok(operations)
}

fn is_admin_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/admin")
        || lower.starts_with("/internal")
        || lower.starts_with("/mgmt")
        || lower.starts_with("/api/admin")
        || lower.starts_with("/api/internal")
}

fn is_public_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/health")
        || lower.starts_with("/metrics")
        || lower.starts_with("/docs")
        || lower.starts_with("/swagger")
        || lower.starts_with("/login")
        || lower.starts_with("/auth/login")
        || lower.starts_with("/.well-known")
}

fn parse_parameters(
    ctx: &mut ParserContext,
    val: Option<&Value>,
    _version: SpecVersion,
) -> Result<Vec<Parameter>, ApiError> {
    let mut params = Vec::new();
    let arr = match val.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Ok(params),
    };

    for item in arr {
        let name = match item.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let location = match item.get("in").and_then(|i| i.as_str()) {
            Some("path") => ParamLocation::Path,
            Some("query") => ParamLocation::Query,
            Some("header") => ParamLocation::Header,
            Some("cookie") => ParamLocation::Cookie,
            Some("body") => ParamLocation::Body,
            _ => continue,
        };

        let required = item
            .get("required")
            .and_then(|r| r.as_bool())
            .unwrap_or(location == ParamLocation::Path);

        // Schema resolution: in OpenAPI 3.x schema is under param.schema.
        // In Swagger 2.0 query/path params have schema fields at param level.
        let schema_val = item.get("schema").unwrap_or(item);
        let mut call_stack = HashSet::new();
        let schema_node = parse_schema_node(ctx, schema_val, 0, &mut call_stack)?;

        params.push(Parameter {
            name,
            location,
            required,
            schema: Some(Box::new(schema_node)),
        });
    }

    Ok(params)
}

fn parse_openapi_request_body(
    ctx: &mut ParserContext,
    val: Option<&Value>,
) -> Result<Option<RequestBody>, ApiError> {
    let body_val = match val {
        Some(v) => v,
        None => return Ok(None),
    };

    let required = body_val
        .get("required")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);

    let mut content_types = HashMap::new();
    if let Some(content_obj) = body_val.get("content").and_then(|c| c.as_object()) {
        for (mime, media_type) in content_obj {
            if let Some(schema_val) = media_type.get("schema") {
                let mut call_stack = HashSet::new();
                let schema_node = parse_schema_node(ctx, schema_val, 0, &mut call_stack)?;
                content_types.insert(mime.clone(), Box::new(schema_node));
            }
        }
    }

    Ok(Some(RequestBody {
        required,
        content_types,
    }))
}

fn parse_swagger_body_parameter(
    ctx: &mut ParserContext,
    val: Option<&Value>,
) -> Result<Option<RequestBody>, ApiError> {
    let arr = match val.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Ok(None),
    };

    for item in arr {
        if item.get("in").and_then(|i| i.as_str()) == Some("body") {
            let required = item
                .get("required")
                .and_then(|r| r.as_bool())
                .unwrap_or(false);

            let mut content_types = HashMap::new();
            if let Some(schema_val) = item.get("schema") {
                let mut call_stack = HashSet::new();
                let schema_node = parse_schema_node(ctx, schema_val, 0, &mut call_stack)?;
                content_types.insert("application/json".to_string(), Box::new(schema_node));
            }

            return Ok(Some(RequestBody {
                required,
                content_types,
            }));
        }
    }

    Ok(None)
}

fn parse_responses(
    ctx: &mut ParserContext,
    val: Option<&Value>,
    version: SpecVersion,
) -> Result<HashMap<String, Response>, ApiError> {
    let mut map = HashMap::new();
    let resp_obj = match val.and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Ok(map),
    };

    for (code, resp_val) in resp_obj {
        let description = resp_val
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();

        let mut content_types = HashMap::new();

        match version {
            SpecVersion::OpenApi30 | SpecVersion::OpenApi31 => {
                if let Some(content) = resp_val.get("content").and_then(|c| c.as_object()) {
                    for (mime, media) in content {
                        if let Some(schema_val) = media.get("schema") {
                            let mut call_stack = HashSet::new();
                            let node = parse_schema_node(ctx, schema_val, 0, &mut call_stack)?;
                            content_types.insert(mime.clone(), Box::new(node));
                        }
                    }
                }
            }
            SpecVersion::Swagger2 => {
                if let Some(schema_val) = resp_val.get("schema") {
                    let mut call_stack = HashSet::new();
                    let node = parse_schema_node(ctx, schema_val, 0, &mut call_stack)?;
                    content_types.insert("application/json".to_string(), Box::new(node));
                }
            }
        }

        map.insert(
            code.clone(),
            Response {
                description,
                content_types,
            },
        );
    }

    Ok(map)
}

fn parse_schema_node(
    ctx: &mut ParserContext,
    val: &Value,
    depth: usize,
    call_stack: &mut HashSet<String>,
) -> Result<SchemaNode, ApiError> {
    if depth > MAX_REF_DEPTH {
        return Err(ApiError::RecursionLimitExceeded(depth));
    }

    ctx.total_nodes += 1;
    if ctx.total_nodes > 50_000 {
        return Err(ApiError::InvalidSpec(
            "Specification schema node budget exceeded (50,000 nodes)".to_string(),
        ));
    }

    // Check $ref
    if let Some(ref_str) = val.get("$ref").and_then(|r| r.as_str()) {
        // Security check: reject network URIs to prevent SSRF
        if ref_str.starts_with("http://")
            || ref_str.starts_with("https://")
            || ref_str.starts_with("ftp://")
        {
            return Err(ApiError::ExternalNetworkRefForbidden(ref_str.to_string()));
        }

        // Branch cycle tracking: if already in branch call stack, gracefully terminate recursion
        if call_stack.contains(ref_str) {
            return Ok(SchemaNode {
                ref_path: Some(ref_str.to_string()),
                ..Default::default()
            });
        }

        // Check if cached
        if let Some(cached) = ctx.schema_cache.get(ref_str) {
            return Ok((**cached).clone());
        }

        // Resolve reference
        let resolved_val = resolve_pointer(ctx.root, ref_str, ctx.spec_dir.as_deref())?;
        call_stack.insert(ref_str.to_string());
        let parsed = parse_schema_node(ctx, &resolved_val, depth + 1, call_stack)?;
        call_stack.remove(ref_str);

        let mut node = parsed;
        node.ref_path = Some(ref_str.to_string());
        ctx.schema_cache
            .insert(ref_str.to_string(), Box::new(node.clone()));
        return Ok(node);
    }

    let schema_type = val.get("type").and_then(|t| {
        if let Some(s) = t.as_str() {
            Some(s.to_string())
        } else if let Some(arr) = t.as_array() {
            // OpenAPI 3.1 type union (e.g. ["string", "null"])
            arr.iter().find_map(|v| v.as_str()).map(|s| s.to_string())
        } else {
            None
        }
    });

    let format = val
        .get("format")
        .and_then(|f| f.as_str())
        .map(|s| s.to_string());
    let read_only = val
        .get("readOnly")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);
    let write_only = val
        .get("writeOnly")
        .and_then(|w| w.as_bool())
        .unwrap_or(false);
    let minimum = val.get("minimum").and_then(|m| m.as_f64());
    let maximum = val.get("maximum").and_then(|m| m.as_f64());
    let min_length = val
        .get("minLength")
        .and_then(|m| m.as_u64())
        .map(|u| u as usize);
    let max_length = val
        .get("maxLength")
        .and_then(|m| m.as_u64())
        .map(|u| u as usize);
    let pattern = val
        .get("pattern")
        .and_then(|p| p.as_str())
        .map(|s| s.to_string());

    let required = val
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut properties = HashMap::new();
    if let Some(props_obj) = val.get("properties").and_then(|p| p.as_object()) {
        for (prop_name, prop_val) in props_obj {
            let child = parse_schema_node(ctx, prop_val, depth + 1, call_stack)?;
            properties.insert(prop_name.clone(), Box::new(child));
        }
    }

    let items = if let Some(items_val) = val.get("items") {
        let child = parse_schema_node(ctx, items_val, depth + 1, call_stack)?;
        Some(Box::new(child))
    } else {
        None
    };

    Ok(SchemaNode {
        schema_type,
        format,
        properties,
        items,
        required,
        read_only,
        write_only,
        minimum,
        maximum,
        min_length,
        max_length,
        pattern,
        ref_path: None,
    })
}

fn resolve_pointer(
    root: &Value,
    ref_str: &str,
    spec_dir: Option<&Path>,
) -> Result<Value, ApiError> {
    if let Some(pointer) = ref_str.strip_prefix('#') {
        // Internal JSON pointer
        let unescaped = pointer.replace("~1", "/").replace("~0", "~");

        let segments: Vec<&str> = unescaped.split('/').filter(|s| !s.is_empty()).collect();
        let mut curr = root;
        for seg in segments {
            match curr.get(seg) {
                Some(next) => curr = next,
                None => {
                    return Err(ApiError::InvalidSpec(format!(
                        "Unresolvable internal $ref pointer: {}",
                        ref_str
                    )))
                }
            }
        }
        Ok(curr.clone())
    } else if let Some(spec_dir) = spec_dir {
        // Local relative file reference (e.g. "schemas/user.yaml#/definitions/User")
        let (file_path_str, fragment) = match ref_str.split_once('#') {
            Some((f, frag)) => (f, Some(frag)),
            None => (ref_str, None),
        };

        let target_path = spec_dir.join(file_path_str);
        let canonical_dir = spec_dir
            .canonicalize()
            .unwrap_or_else(|_| spec_dir.to_path_buf());
        let canonical_target = target_path
            .canonicalize()
            .map_err(|_| ApiError::InvalidRefPath(format!("File does not exist: {}", ref_str)))?;

        if !canonical_target.starts_with(&canonical_dir) {
            return Err(ApiError::InvalidRefPath(format!(
                "Local $ref path escapes specification directory: {}",
                ref_str
            )));
        }

        let file_content = fs::read_to_string(&canonical_target)?;
        let file_root: Value = if let Ok(val) = serde_json::from_str::<Value>(&file_content) {
            val
        } else {
            serde_yaml::from_str::<Value>(&file_content)?
        };

        if let Some(frag) = fragment {
            let internal_ref = format!("#{}", frag);
            resolve_pointer(&file_root, &internal_ref, Some(&canonical_dir))
        } else {
            Ok(file_root)
        }
    } else {
        Err(ApiError::InvalidSpec(format!(
            "Cannot resolve relative external reference without spec directory: {}",
            ref_str
        )))
    }
}

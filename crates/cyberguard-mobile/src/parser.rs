use crate::error::MobileError;
use crate::models::{
    AndroidApplication, AndroidComponent, AndroidComponentType, AndroidDomainConfig,
    AndroidIntentFilter, AndroidManifest, AndroidNetworkSecurityConfig, AndroidUsesPermission,
    IosAppTransportSecurity, IosAtsExceptionDomain, IosEntitlement, IosPropertyList, IosUrlType,
    MobileDocument, MobileFormat,
};
use flate2::read::DeflateDecoder;
use quick_xml::events::Event;
use quick_xml::reader::Reader as XmlReader;
use std::io::{Cursor, Read};
use std::path::Path;

/// Maximum allowed decompressed manifest entry size (10 MB).
pub const MAX_MANIFEST_SIZE: usize = 10 * 1024 * 1024;

/// Known standard Android resource IDs (android.R.attr.*).
pub const ATTR_DEBUGGABLE: u32 = 0x0101000f;
pub const ATTR_EXPORTED: u32 = 0x01010010;
pub const ATTR_ALLOW_BACKUP: u32 = 0x01010280;
pub const ATTR_USES_CLEARTEXT_TRAFFIC: u32 = 0x010104ec;
pub const ATTR_PERMISSION: u32 = 0x01010006;
pub const ATTR_NAME: u32 = 0x01010003;
pub const ATTR_TARGET_SDK_VERSION: u32 = 0x01010272;
pub const ATTR_MIN_SDK_VERSION: u32 = 0x0101020b;
pub const ATTR_FULL_BACKUP_CONTENT: u32 = 0x010104e1;
pub const ATTR_DATA_EXTRACTION_RULES: u32 = 0x01010667;
pub const ATTR_NETWORK_SECURITY_CONFIG: u32 = 0x0101052b;

/// Ingestion parser for mobile packages (APK/IPA), manifests, and configuration files.
pub struct MobileParser;

impl MobileParser {
    /// Ingests and parses a mobile package or manifest file from the filesystem.
    pub fn parse_file(path: &Path) -> Result<Vec<MobileDocument>, MobileError> {
        let mut file = std::fs::File::open(path)?;
        Self::parse_reader(&mut file, path)
    }

    /// Ingests and parses mobile artifacts from a generic stream with path hint.
    pub fn parse_reader(
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<Vec<MobileDocument>, MobileError> {
        let file_name = path_hint
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if file_name.ends_with(".apk") {
            Self::parse_apk_archive(reader, path_hint)
        } else if file_name.ends_with(".ipa") || file_name.ends_with(".zip") {
            Self::parse_ipa_archive(reader, path_hint)
        } else if file_name.ends_with("network_security_config.xml") {
            let mut raw_bytes = Vec::new();
            reader
                .take((MAX_MANIFEST_SIZE + 1) as u64)
                .read_to_end(&mut raw_bytes)?;
            if raw_bytes.len() > MAX_MANIFEST_SIZE {
                return Err(MobileError::ManifestSizeLimitExceeded {
                    size: raw_bytes.len(),
                    max_allowed: MAX_MANIFEST_SIZE,
                });
            }
            let raw_content = String::from_utf8_lossy(&raw_bytes).to_string();
            let net_config =
                Self::parse_android_network_config(&raw_content, path_hint.to_str().unwrap_or(""))?;
            Ok(vec![MobileDocument {
                format: MobileFormat::AndroidNetworkSecurityConfig,
                file_path: path_hint.to_string_lossy().to_string(),
                android_manifest: None,
                android_network_config: Some(net_config),
                ios_plist: None,
                ios_entitlements: None,
                raw_content,
            }])
        } else if file_name.ends_with(".xml") || file_name == "androidmanifest.xml" {
            let mut raw_bytes = Vec::new();
            reader
                .take((MAX_MANIFEST_SIZE + 1) as u64)
                .read_to_end(&mut raw_bytes)?;
            if raw_bytes.len() > MAX_MANIFEST_SIZE {
                return Err(MobileError::ManifestSizeLimitExceeded {
                    size: raw_bytes.len(),
                    max_allowed: MAX_MANIFEST_SIZE,
                });
            }
            let is_axml = raw_bytes.len() >= 4 && raw_bytes[0..4] == [0x03, 0x00, 0x08, 0x00];
            let manifest = if is_axml {
                Self::parse_android_manifest_axml(&raw_bytes, path_hint.to_str().unwrap_or(""))?
            } else {
                let raw_content = String::from_utf8_lossy(&raw_bytes);
                Self::parse_android_manifest_xml(&raw_content, path_hint.to_str().unwrap_or(""))?
            };
            let raw_content = String::from_utf8_lossy(&raw_bytes).to_string();
            Ok(vec![MobileDocument {
                format: if is_axml {
                    MobileFormat::AndroidBinaryXml
                } else {
                    MobileFormat::AndroidManifestXml
                },
                file_path: path_hint.to_string_lossy().to_string(),
                android_manifest: Some(manifest),
                android_network_config: None,
                ios_plist: None,
                ios_entitlements: None,
                raw_content,
            }])
        } else if file_name.ends_with(".entitlements") {
            let mut raw_bytes = Vec::new();
            reader
                .take((MAX_MANIFEST_SIZE + 1) as u64)
                .read_to_end(&mut raw_bytes)?;
            if raw_bytes.len() > MAX_MANIFEST_SIZE {
                return Err(MobileError::ManifestSizeLimitExceeded {
                    size: raw_bytes.len(),
                    max_allowed: MAX_MANIFEST_SIZE,
                });
            }
            let entitlements =
                Self::parse_ios_entitlements(&raw_bytes, path_hint.to_str().unwrap_or(""))?;
            let raw_content = String::from_utf8_lossy(&raw_bytes).to_string();
            Ok(vec![MobileDocument {
                format: MobileFormat::IosEntitlements,
                file_path: path_hint.to_string_lossy().to_string(),
                android_manifest: None,
                android_network_config: None,
                ios_plist: None,
                ios_entitlements: Some(entitlements),
                raw_content,
            }])
        } else if file_name.ends_with(".plist") || file_name == "info.plist" {
            let mut raw_bytes = Vec::new();
            reader
                .take((MAX_MANIFEST_SIZE + 1) as u64)
                .read_to_end(&mut raw_bytes)?;
            if raw_bytes.len() > MAX_MANIFEST_SIZE {
                return Err(MobileError::ManifestSizeLimitExceeded {
                    size: raw_bytes.len(),
                    max_allowed: MAX_MANIFEST_SIZE,
                });
            }
            let plist = Self::parse_ios_plist(&raw_bytes, path_hint.to_str().unwrap_or(""))?;
            let raw_content = String::from_utf8_lossy(&raw_bytes).to_string();
            Ok(vec![MobileDocument {
                format: MobileFormat::IosInfoPlist,
                file_path: path_hint.to_string_lossy().to_string(),
                android_manifest: None,
                android_network_config: None,
                ios_plist: Some(plist),
                ios_entitlements: None,
                raw_content,
            }])
        } else {
            Err(MobileError::UnrecognizedFormat(
                path_hint.to_string_lossy().to_string(),
            ))
        }
    }

    /// Streaming ZIP extractor that parses an APK archive without loading the full archive into RAM.
    fn parse_apk_archive(
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<Vec<MobileDocument>, MobileError> {
        let entries = Self::extract_targeted_zip_entries(
            reader,
            &["androidmanifest.xml", "network_security_config.xml"],
        )?;

        let mut documents = Vec::new();
        let mut manifest_found = false;

        for (rel_path, bytes) in entries {
            let lower = rel_path.to_ascii_lowercase();
            if lower.ends_with("androidmanifest.xml") {
                let is_axml = bytes.len() >= 4 && bytes[0..4] == [0x03, 0x00, 0x08, 0x00];
                let manifest = if is_axml {
                    Self::parse_android_manifest_axml(&bytes, &rel_path)?
                } else {
                    let xml_str = String::from_utf8_lossy(&bytes);
                    Self::parse_android_manifest_xml(&xml_str, &rel_path)?
                };
                let raw_content = String::from_utf8_lossy(&bytes).to_string();
                documents.push(MobileDocument {
                    format: MobileFormat::AndroidApk,
                    file_path: format!("{}:{}", path_hint.display(), rel_path),
                    android_manifest: Some(manifest),
                    android_network_config: None,
                    ios_plist: None,
                    ios_entitlements: None,
                    raw_content,
                });
                manifest_found = true;
            } else if lower.ends_with("network_security_config.xml") {
                let raw_content = String::from_utf8_lossy(&bytes).to_string();
                let net_cfg = Self::parse_android_network_config(&raw_content, &rel_path)?;
                documents.push(MobileDocument {
                    format: MobileFormat::AndroidNetworkSecurityConfig,
                    file_path: format!("{}:{}", path_hint.display(), rel_path),
                    android_manifest: None,
                    android_network_config: Some(net_cfg),
                    ios_plist: None,
                    ios_entitlements: None,
                    raw_content,
                });
            }
        }

        if !manifest_found {
            return Err(MobileError::MissingManifestInArchive(format!(
                "AndroidManifest.xml not found in APK '{}'",
                path_hint.display()
            )));
        }

        Ok(documents)
    }

    /// Streaming ZIP extractor that parses an IPA archive without loading the full archive into RAM.
    fn parse_ipa_archive(
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<Vec<MobileDocument>, MobileError> {
        let entries = Self::extract_targeted_zip_entries(reader, &["info.plist", ".entitlements"])?;

        let mut documents = Vec::new();
        let mut plist_found = false;

        for (rel_path, bytes) in entries {
            let lower = rel_path.to_ascii_lowercase();
            if lower.ends_with("info.plist") {
                let plist = Self::parse_ios_plist(&bytes, &rel_path)?;
                let raw_content = String::from_utf8_lossy(&bytes).to_string();
                documents.push(MobileDocument {
                    format: MobileFormat::IosIpa,
                    file_path: format!("{}:{}", path_hint.display(), rel_path),
                    android_manifest: None,
                    android_network_config: None,
                    ios_plist: Some(plist),
                    ios_entitlements: None,
                    raw_content,
                });
                plist_found = true;
            } else if lower.ends_with(".entitlements") {
                let entitlements = Self::parse_ios_entitlements(&bytes, &rel_path)?;
                let raw_content = String::from_utf8_lossy(&bytes).to_string();
                documents.push(MobileDocument {
                    format: MobileFormat::IosEntitlements,
                    file_path: format!("{}:{}", path_hint.display(), rel_path),
                    android_manifest: None,
                    android_network_config: None,
                    ios_plist: None,
                    ios_entitlements: Some(entitlements),
                    raw_content,
                });
            }
        }

        if !plist_found {
            return Err(MobileError::MissingManifestInArchive(format!(
                "Info.plist not found in IPA archive '{}'",
                path_hint.display()
            )));
        }

        Ok(documents)
    }

    /// Extract targeted files from a ZIP stream sequentially.
    /// Safely skips non-matching entries and protects against zip bombs.
    pub fn extract_targeted_zip_entries(
        reader: &mut (dyn Read + Send),
        match_suffixes: &[&str],
    ) -> Result<Vec<(String, Vec<u8>)>, MobileError> {
        let mut extracted = Vec::new();
        let mut header_buf = [0u8; 30];

        loop {
            // Read local file header signature
            match reader.read_exact(&mut header_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(MobileError::Io(e)),
            }

            // Check signature: 0x04034b50 (PK\x03\x04)
            if &header_buf[0..4] != b"PK\x03\x04" {
                // Not a local file header; might be Central Directory header (0x02014b50) or end
                break;
            }

            let compression_method = u16::from_le_bytes([header_buf[8], header_buf[9]]);
            let compressed_size = u32::from_le_bytes([
                header_buf[18],
                header_buf[19],
                header_buf[20],
                header_buf[21],
            ]) as usize;
            let uncompressed_size = u32::from_le_bytes([
                header_buf[22],
                header_buf[23],
                header_buf[24],
                header_buf[25],
            ]) as usize;
            let file_name_len = u16::from_le_bytes([header_buf[26], header_buf[27]]) as usize;
            let extra_field_len = u16::from_le_bytes([header_buf[28], header_buf[29]]) as usize;

            let mut name_buf = vec![0u8; file_name_len];
            reader.read_exact(&mut name_buf)?;
            let file_name = String::from_utf8_lossy(&name_buf).to_string();

            // Skip extra field
            if extra_field_len > 0 {
                let mut extra_buf = vec![0u8; extra_field_len];
                reader.read_exact(&mut extra_buf)?;
            }

            let lower_name = file_name.to_ascii_lowercase();
            let matches = match_suffixes.iter().any(|s| lower_name.ends_with(s));

            if matches {
                if uncompressed_size > MAX_MANIFEST_SIZE {
                    return Err(MobileError::ManifestSizeLimitExceeded {
                        size: uncompressed_size,
                        max_allowed: MAX_MANIFEST_SIZE,
                    });
                }

                let mut compressed_data = vec![0u8; compressed_size];
                reader.read_exact(&mut compressed_data)?;

                let decompressed = match compression_method {
                    0 => compressed_data, // Stored
                    8 => {
                        let decoder = DeflateDecoder::new(Cursor::new(compressed_data));
                        let mut out = Vec::new();
                        let mut limited = decoder.take((MAX_MANIFEST_SIZE + 1) as u64);
                        limited
                            .read_to_end(&mut out)
                            .map_err(|e| MobileError::ZipArchive(e.to_string()))?;
                        if out.len() > MAX_MANIFEST_SIZE {
                            return Err(MobileError::ManifestSizeLimitExceeded {
                                size: out.len(),
                                max_allowed: MAX_MANIFEST_SIZE,
                            });
                        }
                        out
                    }
                    other => {
                        return Err(MobileError::ZipArchive(format!(
                            "Unsupported compression method {} in entry '{}'",
                            other, file_name
                        )))
                    }
                };

                extracted.push((file_name, decompressed));
            } else {
                // Skip payload without allocating it into memory
                let mut skipped = 0;
                let mut discard = [0u8; 8192];
                while skipped < compressed_size {
                    let to_read = std::cmp::min(discard.len(), compressed_size - skipped);
                    let read_bytes = reader.read(&mut discard[..to_read])?;
                    if read_bytes == 0 {
                        break;
                    }
                    skipped += read_bytes;
                }
            }
        }

        Ok(extracted)
    }

    /// Parses standard UTF-8 XML `AndroidManifest.xml`.
    pub fn parse_android_manifest_xml(
        xml: &str,
        file_path: &str,
    ) -> Result<AndroidManifest, MobileError> {
        let mut manifest = AndroidManifest::default();
        let mut reader = XmlReader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut current_component: Option<AndroidComponent> = None;
        let mut current_intent_filter: Option<AndroidIntentFilter> = None;
        let mut in_intent_filter = false;

        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = e.name();
                    let tag_name = name.as_ref();
                    match tag_name {
                        "manifest" => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref();
                                if key == "package" {
                                    manifest.package_name = Some(val.to_string());
                                }
                            }
                        }
                        "uses-sdk" => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref();
                                if key.ends_with("minSdkVersion") {
                                    manifest.min_sdk_version = val.parse().ok();
                                } else if key.ends_with("targetSdkVersion") {
                                    manifest.target_sdk_version = val.parse().ok();
                                }
                            }
                        }
                        "application" => {
                            Self::parse_application_attributes(e, &mut manifest.application);
                        }
                        "activity" | "service" | "receiver" | "provider" => {
                            let ctype = match tag_name {
                                "activity" => AndroidComponentType::Activity,
                                "service" => AndroidComponentType::Service,
                                "receiver" => AndroidComponentType::Receiver,
                                _ => AndroidComponentType::Provider,
                            };
                            current_component = Some(Self::parse_component_attributes(e, ctype));
                        }
                        "intent-filter" => {
                            in_intent_filter = true;
                            current_intent_filter = Some(AndroidIntentFilter::default());
                        }
                        "action" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                if key.ends_with("name") {
                                    let val = attr.value.as_ref().to_string();
                                    if let Some(ref mut f) = current_intent_filter {
                                        f.actions.push(val);
                                    }
                                }
                            }
                        }
                        "category" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                if key.ends_with("name") {
                                    let val = attr.value.as_ref().to_string();
                                    if let Some(ref mut f) = current_intent_filter {
                                        f.categories.push(val);
                                    }
                                }
                            }
                        }
                        "data" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref().to_string();
                                if let Some(ref mut f) = current_intent_filter {
                                    if key.ends_with("scheme") {
                                        f.data_schemes.push(val);
                                    } else if key.ends_with("host") {
                                        f.data_hosts.push(val);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = e.name();
                    let tag_name = name.as_ref();
                    match tag_name {
                        "uses-permission" => {
                            let mut perm_name = String::new();
                            let mut max_sdk = None;
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref();
                                if key.ends_with("name") {
                                    perm_name = val.to_string();
                                } else if key.ends_with("maxSdkVersion") {
                                    max_sdk = val.parse().ok();
                                }
                            }
                            if !perm_name.is_empty() {
                                manifest.permissions.push(perm_name.clone());
                                manifest.uses_permissions.push(AndroidUsesPermission {
                                    name: perm_name,
                                    max_sdk_version: max_sdk,
                                });
                            }
                        }
                        "uses-sdk" => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref();
                                if key.ends_with("minSdkVersion") {
                                    manifest.min_sdk_version = val.parse().ok();
                                } else if key.ends_with("targetSdkVersion") {
                                    manifest.target_sdk_version = val.parse().ok();
                                }
                            }
                        }
                        "application" => {
                            Self::parse_application_attributes(e, &mut manifest.application);
                        }
                        "activity" | "service" | "receiver" | "provider" => {
                            let ctype = match tag_name {
                                "activity" => AndroidComponentType::Activity,
                                "service" => AndroidComponentType::Service,
                                "receiver" => AndroidComponentType::Receiver,
                                _ => AndroidComponentType::Provider,
                            };
                            let comp = Self::parse_component_attributes(e, ctype);
                            manifest.application.components.push(comp);
                        }
                        "action" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                if key.ends_with("name") {
                                    let val = attr.value.as_ref().to_string();
                                    if let Some(ref mut f) = current_intent_filter {
                                        f.actions.push(val);
                                    }
                                }
                            }
                        }
                        "category" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                if key.ends_with("name") {
                                    let val = attr.value.as_ref().to_string();
                                    if let Some(ref mut f) = current_intent_filter {
                                        f.categories.push(val);
                                    }
                                }
                            }
                        }
                        "data" if in_intent_filter => {
                            for attr in e.attributes().flatten() {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref().to_string();
                                if let Some(ref mut f) = current_intent_filter {
                                    if key.ends_with("scheme") {
                                        f.data_schemes.push(val);
                                    } else if key.ends_with("host") {
                                        f.data_hosts.push(val);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = e.name();
                    let tag_name = name.as_ref();
                    match tag_name {
                        "intent-filter" => {
                            if let (Some(ref mut comp), Some(filter)) =
                                (&mut current_component, current_intent_filter.take())
                            {
                                comp.intent_filters.push(filter);
                            }
                            in_intent_filter = false;
                        }
                        "activity" | "service" | "receiver" | "provider" => {
                            if let Some(comp) = current_component.take() {
                                manifest.application.components.push(comp);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(MobileError::XmlParse(format!(
                        "Error parsing Android XML at '{}:{}': {}",
                        file_path,
                        reader.buffer_position(),
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(manifest)
    }

    fn parse_application_attributes(
        e: &quick_xml::events::BytesStart<'_>,
        app: &mut AndroidApplication,
    ) {
        for attr in e.attributes().flatten() {
            let key = attr.key.as_ref();
            let val = attr.value.as_ref();
            if key.ends_with("name") {
                app.name = Some(val.to_string());
            } else if key.ends_with("debuggable") {
                app.debuggable = Some(val == "true");
            } else if key.ends_with("allowBackup") {
                app.allow_backup = Some(val == "true");
            } else if key.ends_with("usesCleartextTraffic") {
                app.uses_cleartext_traffic = Some(val == "true");
            } else if key.ends_with("networkSecurityConfig") {
                app.network_security_config = Some(val.to_string());
            } else if key.ends_with("fullBackupContent") {
                app.full_backup_content = Some(val.to_string());
            } else if key.ends_with("dataExtractionRules") {
                app.data_extraction_rules = Some(val.to_string());
            }
        }
    }

    fn parse_component_attributes(
        e: &quick_xml::events::BytesStart<'_>,
        ctype: AndroidComponentType,
    ) -> AndroidComponent {
        let mut name = String::new();
        let mut exported = None;
        let mut permission = None;

        for attr in e.attributes().flatten() {
            let key = attr.key.as_ref();
            let val = attr.value.as_ref();
            if key.ends_with("name") {
                name = val.to_string();
            } else if key.ends_with("exported") {
                exported = Some(val == "true");
            } else if key.ends_with("permission") {
                permission = Some(val.to_string());
            }
        }

        AndroidComponent {
            component_type: ctype,
            name,
            exported,
            permission,
            intent_filters: Vec::new(),
        }
    }

    /// Parses Android Network Security Configuration XML (`network_security_config.xml`).
    pub fn parse_android_network_config(
        xml: &str,
        file_path: &str,
    ) -> Result<AndroidNetworkSecurityConfig, MobileError> {
        let mut config = AndroidNetworkSecurityConfig::default();
        let mut reader = XmlReader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut in_base_config = false;
        let mut current_domain_config: Option<AndroidDomainConfig> = None;
        let mut in_domain_config = false;
        let mut in_domain = false;
        let mut current_domain_include_subdomains = false;

        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = e.name();
                    let tag = name.as_ref();
                    match tag {
                        "base-config" => {
                            in_base_config = true;
                            for attr in e.attributes().flatten() {
                                let k = attr.key.as_ref();
                                let v = attr.value.as_ref();
                                if k.ends_with("cleartextTrafficPermitted") {
                                    config.base_config_cleartext_permitted = Some(v == "true");
                                }
                            }
                        }
                        "domain-config" => {
                            in_domain_config = true;
                            let mut cleartext = None;
                            for attr in e.attributes().flatten() {
                                let k = attr.key.as_ref();
                                let v = attr.value.as_ref();
                                if k.ends_with("cleartextTrafficPermitted") {
                                    cleartext = Some(v == "true");
                                }
                            }
                            current_domain_config = Some(AndroidDomainConfig {
                                domains: Vec::new(),
                                cleartext_traffic_permitted: cleartext,
                                include_subdomains: false,
                            });
                        }
                        "domain" if in_domain_config => {
                            in_domain = true;
                            current_domain_include_subdomains = false;
                            for attr in e.attributes().flatten() {
                                let k = attr.key.as_ref();
                                let v = attr.value.as_ref();
                                if k.ends_with("includeSubdomains") {
                                    current_domain_include_subdomains = v == "true";
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = e.name();
                    let tag = name.as_ref();
                    if tag == "base-config" {
                        for attr in e.attributes().flatten() {
                            let k = attr.key.as_ref();
                            let v = attr.value.as_ref();
                            if k.ends_with("cleartextTrafficPermitted") {
                                config.base_config_cleartext_permitted = Some(v == "true");
                            }
                        }
                    }
                }
                Ok(Event::Text(ref e)) if in_domain => {
                    let text = e.clone().into_inner().trim().to_string();
                    if !text.is_empty() {
                        if let Some(ref mut d_cfg) = current_domain_config {
                            d_cfg.domains.push(text);
                            d_cfg.include_subdomains = current_domain_include_subdomains;
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = e.name();
                    let tag = name.as_ref();
                    match tag {
                        "base-config" => in_base_config = false,
                        "domain-config" => {
                            if let Some(cfg) = current_domain_config.take() {
                                config.domain_configs.push(cfg);
                            }
                            in_domain_config = false;
                        }
                        "domain" => in_domain = false,
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(MobileError::XmlParse(format!(
                        "Error in network security config '{}': {}",
                        file_path, e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        let _ = in_base_config;
        Ok(config)
    }

    /// Parses Android Binary XML (AXML) into canonical `AndroidManifest`.
    /// Handles standard StringPool, ResourceMap (`0x0180`), and element chunks (`0x0102`).
    pub fn parse_android_manifest_axml(
        bytes: &[u8],
        file_path: &str,
    ) -> Result<AndroidManifest, MobileError> {
        if bytes.len() < 8 {
            return Err(MobileError::AxmlDecode(format!(
                "AXML payload too short in '{}'",
                file_path
            )));
        }

        // Header check: RES_XML_TYPE (0x0003), header_size (0x0008) -> 0x00080003
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != 0x00080003 {
            return Err(MobileError::AxmlDecode(format!(
                "Invalid AXML header 0x{:08X} in '{}'",
                magic, file_path
            )));
        }

        let mut offset = 8;
        let mut string_pool: Vec<String> = Vec::new();
        let mut resource_map: Vec<u32> = Vec::new();
        let mut manifest = AndroidManifest::default();
        let mut current_component: Option<AndroidComponent> = None;
        let mut current_intent_filter: Option<AndroidIntentFilter> = None;
        let mut in_intent_filter = false;

        while offset + 8 <= bytes.len() {
            let chunk_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            let _header_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let chunk_size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;

            if chunk_size == 0 || offset + chunk_size > bytes.len() {
                break;
            }

            match chunk_type {
                0x0001 => {
                    // String Pool Chunk (RES_STRING_POOL_TYPE)
                    string_pool = Self::parse_axml_string_pool(&bytes[offset..offset + chunk_size]);
                }
                0x0180 => {
                    // Resource Map Chunk (RES_XML_RESOURCE_MAP_TYPE)
                    let count = (chunk_size - 8) / 4;
                    for i in 0..count {
                        let res_offset = offset + 8 + (i * 4);
                        if res_offset + 4 <= bytes.len() {
                            let res_id = u32::from_le_bytes([
                                bytes[res_offset],
                                bytes[res_offset + 1],
                                bytes[res_offset + 2],
                                bytes[res_offset + 3],
                            ]);
                            resource_map.push(res_id);
                        }
                    }
                }
                0x0102 => {
                    // Start Element Chunk (RES_XML_START_ELEMENT_TYPE)
                    if offset + 36 <= bytes.len() {
                        let name_idx = u32::from_le_bytes([
                            bytes[offset + 20],
                            bytes[offset + 21],
                            bytes[offset + 22],
                            bytes[offset + 23],
                        ]) as usize;
                        let attr_count =
                            u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;

                        let tag_name = string_pool.get(name_idx).cloned().unwrap_or_default();

                        // Parse attributes (each 20 bytes)
                        let mut attrs: Vec<(String, u32, String)> = Vec::new();
                        let attr_start = offset + 36;
                        for i in 0..attr_count {
                            let a_off = attr_start + (i * 20);
                            if a_off + 20 <= bytes.len() {
                                let a_name_idx = u32::from_le_bytes([
                                    bytes[a_off + 4],
                                    bytes[a_off + 5],
                                    bytes[a_off + 6],
                                    bytes[a_off + 7],
                                ]) as usize;
                                let a_raw_val_idx = u32::from_le_bytes([
                                    bytes[a_off + 8],
                                    bytes[a_off + 9],
                                    bytes[a_off + 10],
                                    bytes[a_off + 11],
                                ]);
                                let a_type = bytes[a_off + 15];
                                let a_data = u32::from_le_bytes([
                                    bytes[a_off + 16],
                                    bytes[a_off + 17],
                                    bytes[a_off + 18],
                                    bytes[a_off + 19],
                                ]);

                                let attr_name =
                                    string_pool.get(a_name_idx).cloned().unwrap_or_default();

                                let res_id = resource_map.get(a_name_idx).copied().unwrap_or(0);

                                let attr_value = if a_raw_val_idx != 0xFFFFFFFF {
                                    string_pool
                                        .get(a_raw_val_idx as usize)
                                        .cloned()
                                        .unwrap_or_default()
                                } else if a_type == 0x12 {
                                    // boolean type
                                    if a_data != 0 {
                                        "true".to_string()
                                    } else {
                                        "false".to_string()
                                    }
                                } else {
                                    a_data.to_string()
                                };

                                attrs.push((attr_name, res_id, attr_value));
                            }
                        }

                        // Map AXML tag and attributes to IR
                        match tag_name.as_str() {
                            "manifest" => {
                                for (k, _res, v) in &attrs {
                                    if k == "package" {
                                        manifest.package_name = Some(v.clone());
                                    }
                                }
                            }
                            "uses-sdk" => {
                                for (k, res, v) in &attrs {
                                    if *res == ATTR_MIN_SDK_VERSION || k == "minSdkVersion" {
                                        manifest.min_sdk_version = v.parse().ok();
                                    } else if *res == ATTR_TARGET_SDK_VERSION
                                        || k == "targetSdkVersion"
                                    {
                                        manifest.target_sdk_version = v.parse().ok();
                                    }
                                }
                            }
                            "uses-permission" => {
                                let mut perm_name = String::new();
                                let mut max_sdk = None;
                                for (k, res, v) in &attrs {
                                    if *res == ATTR_NAME || k == "name" {
                                        perm_name = v.clone();
                                    } else if k == "maxSdkVersion" {
                                        max_sdk = v.parse().ok();
                                    }
                                }
                                if !perm_name.is_empty() {
                                    manifest.permissions.push(perm_name.clone());
                                    manifest.uses_permissions.push(AndroidUsesPermission {
                                        name: perm_name,
                                        max_sdk_version: max_sdk,
                                    });
                                }
                            }
                            "application" => {
                                for (k, res, v) in &attrs {
                                    if *res == ATTR_DEBUGGABLE || k == "debuggable" {
                                        manifest.application.debuggable = Some(v == "true");
                                    } else if *res == ATTR_ALLOW_BACKUP || k == "allowBackup" {
                                        manifest.application.allow_backup = Some(v == "true");
                                    } else if *res == ATTR_USES_CLEARTEXT_TRAFFIC
                                        || k == "usesCleartextTraffic"
                                    {
                                        manifest.application.uses_cleartext_traffic =
                                            Some(v == "true");
                                    } else if *res == ATTR_NAME || k == "name" {
                                        manifest.application.name = Some(v.clone());
                                    } else if *res == ATTR_FULL_BACKUP_CONTENT
                                        || k == "fullBackupContent"
                                    {
                                        manifest.application.full_backup_content = Some(v.clone());
                                    } else if *res == ATTR_DATA_EXTRACTION_RULES
                                        || k == "dataExtractionRules"
                                    {
                                        manifest.application.data_extraction_rules =
                                            Some(v.clone());
                                    } else if *res == ATTR_NETWORK_SECURITY_CONFIG
                                        || k == "networkSecurityConfig"
                                    {
                                        manifest.application.network_security_config =
                                            Some(v.clone());
                                    }
                                }
                            }
                            "activity" | "service" | "receiver" | "provider" => {
                                let ctype = match tag_name.as_str() {
                                    "activity" => AndroidComponentType::Activity,
                                    "service" => AndroidComponentType::Service,
                                    "receiver" => AndroidComponentType::Receiver,
                                    _ => AndroidComponentType::Provider,
                                };
                                let mut name = String::new();
                                let mut exported = None;
                                let mut permission = None;

                                for (k, res, v) in &attrs {
                                    if *res == ATTR_NAME || k == "name" {
                                        name = v.clone();
                                    } else if *res == ATTR_EXPORTED || k == "exported" {
                                        exported = Some(v == "true");
                                    } else if *res == ATTR_PERMISSION || k == "permission" {
                                        permission = Some(v.clone());
                                    }
                                }

                                current_component = Some(AndroidComponent {
                                    component_type: ctype,
                                    name,
                                    exported,
                                    permission,
                                    intent_filters: Vec::new(),
                                });
                            }
                            "intent-filter" => {
                                in_intent_filter = true;
                                current_intent_filter = Some(AndroidIntentFilter::default());
                            }
                            "action" if in_intent_filter => {
                                for (k, res, v) in &attrs {
                                    if *res == ATTR_NAME || k == "name" {
                                        if let Some(ref mut f) = current_intent_filter {
                                            f.actions.push(v.clone());
                                        }
                                    }
                                }
                            }
                            "category" if in_intent_filter => {
                                for (k, res, v) in &attrs {
                                    if *res == ATTR_NAME || k == "name" {
                                        if let Some(ref mut f) = current_intent_filter {
                                            f.categories.push(v.clone());
                                        }
                                    }
                                }
                            }
                            "data" if in_intent_filter => {
                                for (k, _res, v) in &attrs {
                                    if k == "scheme" {
                                        if let Some(ref mut f) = current_intent_filter {
                                            f.data_schemes.push(v.clone());
                                        }
                                    } else if k == "host" {
                                        if let Some(ref mut f) = current_intent_filter {
                                            f.data_hosts.push(v.clone());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                0x0103 if offset + 24 <= bytes.len() => {
                    // End Element Chunk (RES_XML_END_ELEMENT_TYPE)
                    let name_idx = u32::from_le_bytes([
                        bytes[offset + 20],
                        bytes[offset + 21],
                        bytes[offset + 22],
                        bytes[offset + 23],
                    ]) as usize;
                    let tag_name = string_pool.get(name_idx).cloned().unwrap_or_default();
                    match tag_name.as_str() {
                        "intent-filter" => {
                            if let (Some(ref mut comp), Some(filter)) =
                                (&mut current_component, current_intent_filter.take())
                            {
                                comp.intent_filters.push(filter);
                            }
                            in_intent_filter = false;
                        }
                        "activity" | "service" | "receiver" | "provider" => {
                            if let Some(comp) = current_component.take() {
                                manifest.application.components.push(comp);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }

            offset += chunk_size;
        }

        Ok(manifest)
    }

    /// Extracts string pool from AXML chunk.
    fn parse_axml_string_pool(chunk: &[u8]) -> Vec<String> {
        if chunk.len() < 28 {
            return Vec::new();
        }

        let string_count = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as usize;
        let flags = u32::from_le_bytes([chunk[16], chunk[17], chunk[18], chunk[19]]);
        let is_utf8 = (flags & (1 << 8)) != 0;
        let strings_start =
            u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]) as usize;

        let mut offsets = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let o_pos = 28 + (i * 4);
            if o_pos + 4 <= chunk.len() {
                let off = u32::from_le_bytes([
                    chunk[o_pos],
                    chunk[o_pos + 1],
                    chunk[o_pos + 2],
                    chunk[o_pos + 3],
                ]) as usize;
                offsets.push(off);
            }
        }

        let mut strings = Vec::with_capacity(string_count);
        for off in offsets {
            let start = strings_start + off;
            if start < chunk.len() {
                if is_utf8 {
                    // In UTF-8 string pool: 1 byte len or 2 bytes, then bytes
                    let mut s_pos = start;
                    let mut str_len = chunk[s_pos] as usize;
                    s_pos += 1;
                    if (str_len & 0x80) != 0 && s_pos < chunk.len() {
                        str_len = ((str_len & 0x7F) << 8) | (chunk[s_pos] as usize);
                        s_pos += 1;
                    }
                    if s_pos + str_len <= chunk.len() {
                        let s = String::from_utf8_lossy(&chunk[s_pos..s_pos + str_len]).to_string();
                        strings.push(s);
                    } else {
                        strings.push(String::new());
                    }
                } else {
                    // UTF-16 string pool: 2 bytes len, then utf-16 LE
                    let mut s_pos = start;
                    if s_pos + 2 <= chunk.len() {
                        let str_len = u16::from_le_bytes([chunk[s_pos], chunk[s_pos + 1]]) as usize;
                        s_pos += 2;
                        let byte_len = str_len * 2;
                        if s_pos + byte_len <= chunk.len() {
                            let mut u16_chars = Vec::with_capacity(str_len);
                            for j in 0..str_len {
                                let c_pos = s_pos + (j * 2);
                                u16_chars
                                    .push(u16::from_le_bytes([chunk[c_pos], chunk[c_pos + 1]]));
                            }
                            strings.push(String::from_utf16_lossy(&u16_chars));
                        } else {
                            strings.push(String::new());
                        }
                    } else {
                        strings.push(String::new());
                    }
                }
            } else {
                strings.push(String::new());
            }
        }

        strings
    }

    /// Parses Apple Property List (`Info.plist`) supporting both UTF-8 XML and binary `bplist00`.
    pub fn parse_ios_plist(bytes: &[u8], file_path: &str) -> Result<IosPropertyList, MobileError> {
        let value: plist::Value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|e| {
            MobileError::PlistParse(format!("Error parsing plist in '{}': {}", file_path, e))
        })?;

        let mut plist = IosPropertyList::default();

        let dict = match value.as_dictionary() {
            Some(d) => d,
            None => {
                return Err(MobileError::PlistParse(format!(
                    "Root plist in '{}' is not a dictionary",
                    file_path
                )))
            }
        };

        for (k, v) in dict {
            // Save raw key for generic secret and keyword analysis
            plist
                .raw_keys
                .insert(k.clone(), serde_json::to_value(v).unwrap_or_default());

            match k.as_str() {
                "CFBundleIdentifier" => {
                    plist.bundle_identifier = v.as_string().map(|s| s.to_string());
                }
                "CFBundleName" => {
                    plist.bundle_name = v.as_string().map(|s| s.to_string());
                }
                "CFBundleVersion" => {
                    plist.bundle_version = v.as_string().map(|s| s.to_string());
                }
                "CFBundleShortVersionString" => {
                    plist.bundle_short_version_string = v.as_string().map(|s| s.to_string());
                }
                "NSAppTransportSecurity" => {
                    if let Some(ats_dict) = v.as_dictionary() {
                        let mut ats = IosAppTransportSecurity {
                            allows_arbitrary_loads: ats_dict
                                .get("NSAllowsArbitraryLoads")
                                .and_then(|val| val.as_boolean()),
                            allows_arbitrary_loads_for_media: ats_dict
                                .get("NSAllowsArbitraryLoadsForMedia")
                                .and_then(|val| val.as_boolean()),
                            allows_arbitrary_loads_in_web_content: ats_dict
                                .get("NSAllowsArbitraryLoadsInWebContent")
                                .and_then(|val| val.as_boolean()),
                            allows_local_networking: ats_dict
                                .get("NSAllowsLocalNetworking")
                                .and_then(|val| val.as_boolean()),
                            exception_domains: std::collections::HashMap::new(),
                        };

                        if let Some(exc_dict) = ats_dict
                            .get("NSExceptionDomains")
                            .and_then(|val| val.as_dictionary())
                        {
                            for (dom, dom_val) in exc_dict {
                                if let Some(dom_dict) = dom_val.as_dictionary() {
                                    ats.exception_domains.insert(dom.clone(), IosAtsExceptionDomain {
                                        includes_subdomains: dom_dict.get("NSIncludesSubdomains").and_then(|v| v.as_boolean()),
                                        exception_allows_insecure_http_loads: dom_dict.get("NSExceptionAllowsInsecureHTTPLoads").and_then(|v| v.as_boolean()),
                                        temporary_exception_allows_insecure_http_loads: dom_dict.get("NSTemporaryExceptionAllowsInsecureHTTPLoads").and_then(|v| v.as_boolean()),
                                        exception_minimum_tls_version: dom_dict.get("NSExceptionMinimumTLSVersion").and_then(|v| v.as_string().map(|s| s.to_string())),
                                    });
                                }
                            }
                        }
                        plist.app_transport_security = Some(ats);
                    }
                }
                "CFBundleURLTypes" => {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(u_dict) = item.as_dictionary() {
                                let mut url_type = IosUrlType {
                                    url_name: u_dict
                                        .get("CFBundleURLName")
                                        .and_then(|val| val.as_string().map(|s| s.to_string())),
                                    schemes: Vec::new(),
                                };
                                if let Some(schemes) = u_dict
                                    .get("CFBundleURLSchemes")
                                    .and_then(|val| val.as_array())
                                {
                                    for s in schemes {
                                        if let Some(s_str) = s.as_string() {
                                            url_type.schemes.push(s_str.to_string());
                                        }
                                    }
                                }
                                plist.url_types.push(url_type);
                            }
                        }
                    }
                }
                key if key.ends_with("UsageDescription") => {
                    if let Some(desc) = v.as_string() {
                        plist
                            .privacy_usage_descriptions
                            .insert(key.to_string(), desc.to_string());
                    }
                }
                _ => {}
            }
        }

        Ok(plist)
    }

    /// Parses iOS application entitlements (`*.entitlements`).
    pub fn parse_ios_entitlements(
        bytes: &[u8],
        file_path: &str,
    ) -> Result<IosEntitlement, MobileError> {
        let value: plist::Value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|e| {
            MobileError::PlistParse(format!(
                "Error parsing entitlements in '{}': {}",
                file_path, e
            ))
        })?;

        let mut ent = IosEntitlement::default();
        let dict = match value.as_dictionary() {
            Some(d) => d,
            None => {
                return Err(MobileError::PlistParse(format!(
                    "Entitlements root in '{}' is not a dictionary",
                    file_path
                )))
            }
        };

        for (k, v) in dict {
            ent.raw_entitlements
                .insert(k.clone(), serde_json::to_value(v).unwrap_or_default());
            match k.as_str() {
                "get-task-allow" => {
                    ent.get_task_allow = v.as_boolean();
                }
                "keychain-access-groups" => {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_string() {
                                ent.keychain_access_groups.push(s.to_string());
                            }
                        }
                    }
                }
                "com.apple.developer.associated-domains" => {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_string() {
                                ent.associated_domains.push(s.to_string());
                            }
                        }
                    }
                }
                "com.apple.security.app-sandbox" => {
                    ent.app_sandbox = v.as_boolean();
                }
                _ => {}
            }
        }

        Ok(ent)
    }
}

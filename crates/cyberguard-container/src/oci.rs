// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Daemonless OCI / Docker image layer inspector and OS package parsers.

use crate::error::ContainerError;
use crate::models::ContainerPackage;
use flate2::read::GzDecoder;
use std::io::Read;

const BLOCK_SIZE: usize = 512;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024; // 16 MB max

/// Daemonless OCI / Docker layer inspector.
#[derive(Clone, Debug, Default)]
pub struct OciInspector;

impl OciInspector {
    pub fn new() -> Self {
        Self
    }

    /// Validates an entry path against Zip-Slip and directory traversal vectors.
    fn validate_path(path: &str) -> Result<(), ContainerError> {
        let trimmed = path.trim();
        if trimmed.starts_with('/')
            || trimmed.starts_with('\\')
            || (trimmed.len() >= 2 && trimmed.chars().nth(1) == Some(':'))
            || trimmed.split(&['/', '\\'][..]).any(|part| part == "..")
        {
            return Err(ContainerError::ZipSlipViolation(path.to_string()));
        }
        Ok(())
    }

    /// Extracts a null-terminated string from a byte slice.
    fn extract_null_terminated_str(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).trim().to_string()
    }

    /// Parses an octal ASCII number from a tar header slice.
    fn parse_octal(bytes: &[u8]) -> usize {
        let s = Self::extract_null_terminated_str(bytes);
        usize::from_str_radix(s.trim(), 8).unwrap_or(0)
    }

    /// Parses Alpine package database format (`/lib/apk/db/installed`).
    pub fn parse_apk_db(content: &str, layer_id: Option<&str>) -> Vec<ContainerPackage> {
        let mut packages = Vec::new();

        for block in content.split("\n\n") {
            let mut name = None;
            let mut version = None;
            let mut arch = None;
            let mut origin = None;

            for line in block.lines() {
                let trimmed = line.trim();
                if let Some(val) = trimmed.strip_prefix("P:") {
                    name = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("V:") {
                    version = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("A:") {
                    arch = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("o:") {
                    origin = Some(val.trim().to_string());
                }
            }

            if let (Some(n), Some(v)) = (name, version) {
                packages.push(ContainerPackage {
                    name: n,
                    version: v,
                    architecture: arch,
                    package_manager: "apk".to_string(),
                    origin,
                    layer_id: layer_id.map(ToString::to_string),
                });
            }
        }

        packages
    }

    /// Parses Debian/Ubuntu package status format (`/var/lib/dpkg/status`).
    pub fn parse_dpkg_status(content: &str, layer_id: Option<&str>) -> Vec<ContainerPackage> {
        let mut packages = Vec::new();

        for block in content.split("\n\n") {
            let mut name = None;
            let mut version = None;
            let mut arch = None;
            let mut origin = None;
            let mut is_installed = false;

            for line in block.lines() {
                let trimmed = line.trim();
                if let Some(val) = trimmed.strip_prefix("Package:") {
                    name = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("Status:") {
                    if val.contains("install ok installed") {
                        is_installed = true;
                    }
                } else if let Some(val) = trimmed.strip_prefix("Version:") {
                    version = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("Architecture:") {
                    arch = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("Source:") {
                    let src = val.split_whitespace().next().unwrap_or(val).trim();
                    origin = Some(src.to_string());
                }
            }

            if is_installed {
                if let (Some(n), Some(v)) = (name, version) {
                    packages.push(ContainerPackage {
                        name: n,
                        version: v,
                        architecture: arch,
                        package_manager: "dpkg".to_string(),
                        origin,
                        layer_id: layer_id.map(ToString::to_string),
                    });
                }
            }
        }

        packages
    }

    /// Inspects an uncompressed or gzip-compressed tar archive stream without writing to disk.
    pub fn inspect_tar_stream<R: Read>(
        &self,
        mut reader: R,
    ) -> Result<Vec<ContainerPackage>, ContainerError> {
        let mut magic = [0u8; 2];
        let bytes_read = reader.read(&mut magic)?;
        if bytes_read == 0 {
            return Ok(Vec::new());
        }

        if bytes_read == 2 && magic == [0x1F, 0x8B] {
            // Gzip compressed
            let chained = (&magic[..]).chain(reader);
            let decoder = GzDecoder::new(chained);
            self.inspect_raw_tar_stream(decoder)
        } else {
            // Uncompressed tar
            let chained = (&magic[..bytes_read]).chain(reader);
            self.inspect_raw_tar_stream(chained)
        }
    }

    /// Reads raw 512-byte POSIX tar blocks in a single streaming pass.
    fn inspect_raw_tar_stream<R: Read>(
        &self,
        mut reader: R,
    ) -> Result<Vec<ContainerPackage>, ContainerError> {
        let mut packages = Vec::new();
        let mut header = [0u8; BLOCK_SIZE];

        loop {
            let bytes_read = match reader.read_exact(&mut header) {
                Ok(()) => BLOCK_SIZE,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ContainerError::Io(e)),
            };

            if bytes_read == 0 || header.iter().all(|&b| b == 0) {
                // Two consecutive zero blocks or end of file
                break;
            }

            let name = Self::extract_null_terminated_str(&header[..100]);
            let prefix = Self::extract_null_terminated_str(&header[345..500]);
            let full_path = if !prefix.is_empty() {
                format!("{}/{}", prefix, name)
            } else {
                name
            };

            // Enforce Zip-Slip check immediately
            Self::validate_path(&full_path)?;

            let size = Self::parse_octal(&header[124..136]);
            let typeflag = header[156];
            let data_blocks_len = size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;

            let norm_path = full_path.trim_start_matches("./");

            let is_apk =
                norm_path == "lib/apk/db/installed" || norm_path.ends_with("/lib/apk/db/installed");
            let is_dpkg =
                norm_path == "var/lib/dpkg/status" || norm_path.ends_with("/var/lib/dpkg/status");

            if (is_apk || is_dpkg)
                && (typeflag == b'0' || typeflag == 0)
                && size <= MAX_MANIFEST_BYTES
            {
                let mut data_buf = vec![0u8; size];
                reader.read_exact(&mut data_buf)?;

                let padding = data_blocks_len - size;
                if padding > 0 {
                    let mut pad_buf = vec![0u8; padding];
                    reader.read_exact(&mut pad_buf)?;
                }

                if let Ok(content_str) = std::str::from_utf8(&data_buf) {
                    if is_apk {
                        packages.extend(Self::parse_apk_db(content_str, None));
                    } else if is_dpkg {
                        packages.extend(Self::parse_dpkg_status(content_str, None));
                    }
                }
            } else {
                // Discard data blocks without storing in memory
                let mut discarded = 0;
                let mut discard_buf = [0u8; 4096];
                while discarded < data_blocks_len {
                    let to_read = (data_blocks_len - discarded).min(4096);
                    reader.read_exact(&mut discard_buf[..to_read])?;
                    discarded += to_read;
                }
            }
        }

        Ok(packages)
    }
}

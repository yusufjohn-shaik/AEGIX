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

use cyberguard_container::oci::OciInspector;
use std::io::Cursor;

/// Helper to create a minimal 512-byte POSIX tar header
fn create_tar_entry(path: &str, content: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 512];
    let path_bytes = path.as_bytes();
    header[..path_bytes.len().min(100)].copy_from_slice(&path_bytes[..path_bytes.len().min(100)]);

    // Size in octal ASCII at bytes 124..136
    let size_str = format!("{:011o} ", content.len());
    header[124..136].copy_from_slice(size_str.as_bytes());

    // Typeflag '0' at byte 156
    header[156] = b'0';

    // Magic "ustar\0" at bytes 257..263
    header[257..263].copy_from_slice(b"ustar\0");

    let mut data = Vec::new();
    data.extend_from_slice(&header);
    data.extend_from_slice(content);

    // Pad data to multiple of 512
    let remainder = content.len() % 512;
    if remainder != 0 {
        data.extend_from_slice(&vec![0u8; 512 - remainder]);
    }

    data
}

#[test]
fn test_inspect_alpine_layer_packages() {
    let apk_db = "\
P:musl
V:1.2.5-r0
A:x86_64
o:musl

P:libssl3
V:3.3.1-r0
A:x86_64
o:openssl
";
    let mut tar_bytes = create_tar_entry("lib/apk/db/installed", apk_db.as_bytes());
    // Append two 512-byte zero blocks for end of archive
    tar_bytes.extend_from_slice(&vec![0u8; 1024]);

    let inspector = OciInspector::new();
    let packages = inspector
        .inspect_tar_stream(Cursor::new(tar_bytes))
        .expect("Tar inspection succeeds");

    assert_eq!(
        packages.len(),
        2,
        "Expected 2 packages, got: {:?}",
        packages
    );

    let musl = packages.iter().find(|p| p.name == "musl").unwrap();
    assert_eq!(musl.version, "1.2.5-r0");
    assert_eq!(musl.package_manager, "apk");
    assert_eq!(musl.origin.as_deref(), Some("musl"));

    let libssl = packages.iter().find(|p| p.name == "libssl3").unwrap();
    assert_eq!(libssl.version, "3.3.1-r0");
    assert_eq!(libssl.origin.as_deref(), Some("openssl"));
}

#[test]
fn test_inspect_debian_layer_packages() {
    let dpkg_status = "\
Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9+deb12u7
Source: glibc

Package: old-uninstalled-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0.0
";
    let mut tar_bytes = create_tar_entry("var/lib/dpkg/status", dpkg_status.as_bytes());
    tar_bytes.extend_from_slice(&vec![0u8; 1024]);

    let inspector = OciInspector::new();
    let packages = inspector
        .inspect_tar_stream(Cursor::new(tar_bytes))
        .expect("Tar inspection succeeds");

    assert_eq!(packages.len(), 1, "Must only extract installed packages");
    let libc = &packages[0];
    assert_eq!(libc.name, "libc6");
    assert_eq!(libc.version, "2.36-9+deb12u7");
    assert_eq!(libc.package_manager, "dpkg");
    assert_eq!(libc.origin.as_deref(), Some("glibc"));
}

#[test]
fn test_zip_slip_security_rejection() {
    let mut malicious_tar = create_tar_entry("../../etc/shadow", b"root:secret");
    malicious_tar.extend_from_slice(&vec![0u8; 1024]);

    let inspector = OciInspector::new();
    let result = inspector.inspect_tar_stream(Cursor::new(malicious_tar));

    assert!(result.is_err(), "Zip-Slip path must be rejected with error");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Zip-Slip"),
        "Error message must specify Zip-Slip: {}",
        err
    );
}

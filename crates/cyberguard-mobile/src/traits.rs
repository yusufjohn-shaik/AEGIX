use crate::error::MobileError;
use crate::models::{
    AndroidManifest, AndroidNetworkSecurityConfig, IosEntitlement, IosPropertyList, MobileDocument,
    MobileFinding, MobileReport,
};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

/// Primary orchestrator trait for Mobile Security Engine static analysis.
#[async_trait]
pub trait MobileScanner: Send + Sync {
    /// Evaluates pre-parsed mobile documents in memory.
    async fn scan(&self, documents: &[MobileDocument]) -> Result<MobileReport, MobileError>;

    /// Ingests, parses, and evaluates a mobile manifest, plist, or APK/IPA archive from filesystem.
    async fn scan_file(&self, path: &Path) -> Result<MobileReport, MobileError>;

    /// Traverses a mobile project folder or package repository recursively.
    async fn scan_directory(&self, dir_path: &Path) -> Result<MobileReport, MobileError>;

    /// Ingests and evaluates mobile configuration from a generic reader stream (e.g. STDIN or memory buffer).
    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<MobileReport, MobileError>;
}

/// Static security auditor for Android application packages, manifests, and configs.
pub trait AndroidAuditor: Send + Sync {
    /// Audits an Android Manifest against rules CG-MOB-001, 002, 003, 004, 005, and 010.
    fn audit_manifest(
        &self,
        manifest: &AndroidManifest,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError>;

    /// Audits Android network security configurations (res/xml/network_security_config.xml).
    fn audit_network_config(
        &self,
        config: &AndroidNetworkSecurityConfig,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError>;
}

/// Static security auditor for iOS application bundles, property lists, and entitlements.
pub trait IosAuditor: Send + Sync {
    /// Audits an iOS Info.plist against rules CG-MOB-006, 007, 008, and 010.
    fn audit_plist(
        &self,
        plist: &IosPropertyList,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError>;

    /// Audits iOS application entitlements against rule CG-MOB-009 and 010.
    fn audit_entitlements(
        &self,
        entitlements: &IosEntitlement,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError>;
}

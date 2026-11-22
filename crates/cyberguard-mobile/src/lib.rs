//! Mobile Security Static Analysis Engine (`cyberguard-mobile` / `aegix-mobile`).
//!
//! Provides static application security testing (SAST) and configuration auditing
//! for Android packages/manifests (`.apk`, `AndroidManifest.xml`, `network_security_config.xml`)
//! and iOS bundles/plists (`.ipa`, `Info.plist`, `*.entitlements`).

#![deny(unsafe_code)]

pub mod android;
pub mod error;
pub mod ios;
pub mod models;
pub mod parser;
pub mod traits;

pub use android::DefaultAndroidAuditor;
pub use error::MobileError;
pub use ios::DefaultIosAuditor;
pub use models::*;
pub use parser::*;
pub use traits::*;

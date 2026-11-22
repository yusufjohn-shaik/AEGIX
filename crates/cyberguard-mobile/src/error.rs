use thiserror::Error;

/// Strongly typed errors encountered during mobile security analysis.
#[derive(Error, Debug)]
pub enum MobileError {
    #[error("I/O error reading mobile package or manifest: {0}")]
    Io(#[from] std::io::Error),

    #[error("XML deserialization error in mobile manifest: {0}")]
    XmlParse(String),

    #[error("Property list (plist) deserialization error: {0}")]
    PlistParse(String),

    #[error("Binary AXML (Android Binary XML) decoding error: {0}")]
    AxmlDecode(String),

    #[error("ZIP archive decompression or streaming error in mobile package: {0}")]
    ZipArchive(String),

    #[error("Mobile archive file size limit exceeded: {size} bytes exceeds maximum allowed ceiling of {max_allowed} bytes")]
    FileSizeLimitExceeded { size: usize, max_allowed: usize },

    #[error("Extracted manifest size limit exceeded: {size} bytes exceeds maximum allowed ceiling of {max_allowed} bytes")]
    ManifestSizeLimitExceeded { size: usize, max_allowed: usize },

    #[error("Unrecognized or unsupported mobile file format for target: '{0}'")]
    UnrecognizedFormat(String),

    #[error("Missing mandatory target manifest in archive: '{0}'")]
    MissingManifestInArchive(String),

    #[error("SARIF v2.1.0 telemetry export error: {0}")]
    SarifExport(String),
}

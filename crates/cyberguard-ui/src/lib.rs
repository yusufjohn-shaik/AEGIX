//! # CyberGuard UI (`cyberguard-ui` / `aegix-ui`)
//!
//! Executive security reporting, metric aggregation, compliance scorecards,
//! standalone single-file HTML generator, and terminal dashboard widgets for Aegix.

#![deny(unsafe_code)]

pub mod aggregator;
pub mod error;
pub mod html;
pub mod models;
pub mod terminal;
pub mod traits;

pub use aggregator::DefaultMetricsAggregator;
pub use error::UiError;
pub use html::DefaultHtmlReportGenerator;
pub use models::*;
pub use terminal::DefaultTerminalDashboard;
pub use traits::*;

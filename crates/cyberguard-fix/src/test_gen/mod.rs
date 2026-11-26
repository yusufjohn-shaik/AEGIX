pub mod go;
pub mod javascript;
pub mod python;
pub mod rust;

use crate::error::FixError;
use crate::models::{EradicationTest, SourceLanguage, SurgicalPatch};
use crate::traits::TestGenerator;

#[derive(Debug, Default, Clone)]
pub struct DefaultTestGenerator;

impl DefaultTestGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl TestGenerator for DefaultTestGenerator {
    fn generate_test(
        &self,
        patch: &SurgicalPatch,
        lang: SourceLanguage,
    ) -> Result<EradicationTest, FixError> {
        match lang {
            SourceLanguage::Python => python::generate_python_test(patch),
            SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
                javascript::generate_javascript_test(patch, lang)
            }
            SourceLanguage::Go => go::generate_go_test(patch),
            SourceLanguage::Rust => rust::generate_rust_test(patch),
        }
    }
}

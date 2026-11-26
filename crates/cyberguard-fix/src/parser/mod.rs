pub mod go;
pub mod javascript;
pub mod python;
pub mod rust;

use crate::error::FixError;
use crate::models::{ParsedSourceFile, SourceLanguage};
use crate::traits::AstParser;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct MultiLanguageAstParser;

impl MultiLanguageAstParser {
    pub fn new() -> Self {
        Self
    }
}

impl AstParser for MultiLanguageAstParser {
    fn parse(
        &self,
        path: &Path,
        content: &str,
        lang: SourceLanguage,
    ) -> Result<ParsedSourceFile, FixError> {
        match lang {
            SourceLanguage::Python => python::parse_python(path, content),
            SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
                javascript::parse_javascript(path, content, lang)
            }
            SourceLanguage::Go => go::parse_go(path, content),
            SourceLanguage::Rust => rust::parse_rust(path, content),
        }
    }
}

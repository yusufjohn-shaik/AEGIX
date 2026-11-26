use crate::diff::{apply_patches_to_content, generate_unified_diff};
use crate::error::FixError;
use crate::models::{
    FixScanOptions, ParsedSourceFile, RemediationExecutionResult, RemediationPlan, SourceLanguage,
    SurgicalPatch,
};
use crate::parser::MultiLanguageAstParser;
use crate::synthesizer::DefaultPatchSynthesizer;
use crate::taint::DefaultTaintAnalyzer;
use crate::test_gen::DefaultTestGenerator;
use crate::traits::{AstParser, PatchSynthesizer, RemediationEngine, TaintAnalyzer, TestGenerator};
use async_trait::async_trait;
use cyberguard_core::sarif::SarifLog;
use cyberguard_sast::context::ScanContext;
use cyberguard_sast::walker::collect_source_files;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub struct FixEngine {
    parser: Box<dyn AstParser>,
    taint_analyzer: Box<dyn TaintAnalyzer>,
    synthesizer: Box<dyn PatchSynthesizer>,
    test_generator: Box<dyn TestGenerator>,
}

impl Default for FixEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FixEngine {
    pub fn new() -> Self {
        Self {
            parser: Box::new(MultiLanguageAstParser::new()),
            taint_analyzer: Box::new(DefaultTaintAnalyzer::new()),
            synthesizer: Box::new(DefaultPatchSynthesizer::new()),
            test_generator: Box::new(DefaultTestGenerator::new()),
        }
    }

    pub fn with_components(
        parser: Box<dyn AstParser>,
        taint_analyzer: Box<dyn TaintAnalyzer>,
        synthesizer: Box<dyn PatchSynthesizer>,
        test_generator: Box<dyn TestGenerator>,
    ) -> Self {
        Self {
            parser,
            taint_analyzer,
            synthesizer,
            test_generator,
        }
    }
}

#[async_trait]
impl RemediationEngine for FixEngine {
    async fn plan_path(
        &self,
        target: &Path,
        options: &FixScanOptions,
    ) -> Result<RemediationPlan, FixError> {
        if !target.exists() {
            return Err(FixError::TargetNotFound(target.to_path_buf()));
        }

        let mut all_patches = Vec::new();
        let mut all_diffs = Vec::new();
        let mut all_tests = Vec::new();
        let mut warnings = Vec::new();
        let mut detected_lang = SourceLanguage::Python;

        // If target is a single file
        let files = if target.is_file() {
            vec![target.to_path_buf()]
        } else {
            let scan_ctx = ScanContext::new(target.to_path_buf());
            collect_source_files(&scan_ctx)
        };

        for file_path in files {
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let lang = if let Some(opt_lang) = options.language_override {
                opt_lang
            } else if let Some(detected) = SourceLanguage::from_extension(ext) {
                detected
            } else {
                continue;
            };

            detected_lang = lang;

            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            if options.max_file_size > 0 && content.len() as u64 > options.max_file_size {
                warnings.push(format!(
                    "File {} exceeds max size limit, skipping",
                    file_path.display()
                ));
                continue;
            }

            let parsed: ParsedSourceFile = match self.parser.parse(&file_path, &content, lang) {
                Ok(p) => p,
                Err(e) => {
                    warnings.push(format!("Parse error in {}: {}", file_path.display(), e));
                    continue;
                }
            };

            let flows = match self.taint_analyzer.analyze(&parsed) {
                Ok(f) => f,
                Err(e) => {
                    warnings.push(format!("Taint error in {}: {}", file_path.display(), e));
                    continue;
                }
            };

            let mut file_patches = Vec::new();
            for flow in &flows {
                if let Some(rule_filters) = &options.rules_filter {
                    let rule_matches = match flow.sink_kind {
                        crate::models::TaintSinkKind::SqlExecution => {
                            rule_filters.contains(&"CG-SQLI-001".to_string())
                        }
                        crate::models::TaintSinkKind::CommandExecution => {
                            rule_filters.contains(&"CG-CMDI-001".to_string())
                        }
                        crate::models::TaintSinkKind::PathTraversal => {
                            rule_filters.contains(&"CG-PATH-001".to_string())
                        }
                        crate::models::TaintSinkKind::HardcodedSecret => {
                            rule_filters.contains(&"CG-SECR-001".to_string())
                        }
                    };
                    if !rule_matches {
                        continue;
                    }
                }

                if let Some(patch) = self.synthesizer.synthesize(flow, &parsed)? {
                    if options.generate_tests {
                        if let Ok(test) = self.test_generator.generate_test(&patch, lang) {
                            all_tests.push(test);
                        }
                    }
                    file_patches.push(patch);
                }
            }

            if !file_patches.is_empty() {
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                let mut patches_clone = file_patches.clone();
                match apply_patches_to_content(&lines, &mut patches_clone, lang) {
                    Ok(modified_content) => {
                        let diff = generate_unified_diff(&content, &modified_content, &file_path);
                        all_diffs.push(diff);
                        all_patches.extend(file_patches);
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "Failed to generate diff for {}: {}",
                            file_path.display(),
                            e
                        ));
                    }
                }
            }
        }

        let total = all_patches.len();
        Ok(RemediationPlan {
            target_path: target.to_path_buf(),
            language: detected_lang,
            total_vulnerabilities_detected: total,
            remediated_count: total,
            unfixable_count: 0,
            patches: all_patches,
            diffs: all_diffs,
            tests: all_tests,
            warnings,
        })
    }

    async fn plan_sarif(
        &self,
        target: &Path,
        sarif: &SarifLog,
        options: &FixScanOptions,
    ) -> Result<RemediationPlan, FixError> {
        let mut filtered_options = options.clone();
        let mut rules = Vec::new();
        for run in &sarif.runs {
            for result in &run.results {
                if !rules.contains(&result.rule_id) {
                    rules.push(result.rule_id.clone());
                }
            }
        }
        filtered_options.rules_filter = Some(rules);
        self.plan_path(target, &filtered_options).await
    }

    async fn apply_plan(
        &self,
        plan: &RemediationPlan,
    ) -> Result<RemediationExecutionResult, FixError> {
        let start = Instant::now();
        let mut applied_count = 0;
        let mut modified_files = Vec::new();
        let mut written_test_files = Vec::new();
        let mut failed_patches = Vec::new();

        // Group patches by file
        let mut patches_by_file: std::collections::HashMap<PathBuf, Vec<SurgicalPatch>> =
            std::collections::HashMap::new();
        for patch in &plan.patches {
            patches_by_file
                .entry(patch.file_path.clone())
                .or_default()
                .push(patch.clone());
        }

        for (file_path, mut patches) in patches_by_file {
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    failed_patches.push(format!("Read failure for {}: {}", file_path.display(), e));
                    continue;
                }
            };

            let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            match apply_patches_to_content(&lines, &mut patches, plan.language) {
                Ok(new_content) => {
                    if let Err(e) = fs::write(&file_path, new_content) {
                        failed_patches.push(format!(
                            "Write failure for {}: {}",
                            file_path.display(),
                            e
                        ));
                    } else {
                        applied_count += patches.len();
                        modified_files.push(file_path);
                    }
                }
                Err(e) => {
                    failed_patches.push(format!(
                        "Patch conflict in {}: {}",
                        file_path.display(),
                        e
                    ));
                }
            }
        }

        // Write generated tests if any
        for test in &plan.tests {
            if let Some(parent) = test.test_file_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if fs::write(&test.test_file_path, &test.test_code).is_ok() {
                written_test_files.push(test.test_file_path.clone());
            }
        }

        Ok(RemediationExecutionResult {
            applied_patches: applied_count,
            modified_files,
            written_test_files,
            failed_patches,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

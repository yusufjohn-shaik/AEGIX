use crate::error::FixError;
use crate::models::{DiffChunk, SourceLanguage, SurgicalPatch, UnifiedDiff};
use std::path::Path;

/// Applies multiple surgical patches to lines in DESCENDING order (bottom-to-top)
/// to prevent line offset drift. Verifies that patches do not overlap.
pub fn apply_patches_to_content(
    original_lines: &[String],
    patches: &mut [SurgicalPatch],
    lang: SourceLanguage,
) -> Result<String, FixError> {
    if patches.is_empty() {
        return Ok(original_lines.join("\n"));
    }

    // Sort descending by target_line_start
    patches.sort_by_key(|a| std::cmp::Reverse(a.target_line_start));

    // Detect overlap conflicts
    for i in 0..patches.len().saturating_sub(1) {
        let p_higher = &patches[i]; // higher line number
        let p_lower = &patches[i + 1]; // lower line number
        if p_lower.target_line_end >= p_higher.target_line_start {
            return Err(FixError::PatchConflict {
                line: p_higher.target_line_start,
                details: format!(
                    "Patch '{}' (lines {}-{}) overlaps with patch '{}' (lines {}-{})",
                    p_lower.id,
                    p_lower.target_line_start,
                    p_lower.target_line_end,
                    p_higher.id,
                    p_higher.target_line_start,
                    p_higher.target_line_end
                ),
            });
        }
    }

    let mut result_lines = original_lines.to_vec();
    let mut collected_imports: Vec<String> = Vec::new();

    for patch in patches.iter() {
        let start = patch.target_line_start.saturating_sub(1);
        let end = patch.target_line_end.min(result_lines.len());

        let replacement: Vec<String> = patch
            .replacement_content
            .lines()
            .map(|s| s.to_string())
            .collect();

        if start <= result_lines.len() {
            result_lines.splice(start..end, replacement);
        }

        for imp in &patch.required_imports {
            if !collected_imports.contains(imp) {
                collected_imports.push(imp.clone());
            }
        }
    }

    // Inject required imports at top of file if any
    if !collected_imports.is_empty() {
        inject_required_imports(&mut result_lines, &collected_imports, lang);
    }

    Ok(result_lines.join("\n"))
}

fn inject_required_imports(lines: &mut Vec<String>, imports: &[String], lang: SourceLanguage) {
    let mut insert_idx = 0;

    match lang {
        SourceLanguage::Python => {
            // Find insertion point after from __future__ or docstrings
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("from __future__") || trimmed.starts_with('#') {
                    insert_idx = idx + 1;
                }
            }
            for imp in imports.iter().rev() {
                lines.insert(insert_idx, format!("import {}", imp));
            }
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            for imp in imports.iter().rev() {
                lines.insert(0, format!("const {} = require('{}');", imp, imp));
            }
        }
        SourceLanguage::Go => {
            for (idx, line) in lines.iter().enumerate() {
                if line.trim().starts_with("package ") {
                    insert_idx = idx + 1;
                    break;
                }
            }
            for imp in imports.iter().rev() {
                lines.insert(insert_idx, format!("import \"{}\"", imp));
            }
        }
        SourceLanguage::Rust => {
            for imp in imports.iter().rev() {
                lines.insert(0, format!("use {};", imp));
            }
        }
    }
}

/// Generates standard POSIX unified diff (`diff -u`) with hunk coalescing
pub fn generate_unified_diff(original: &str, modified: &str, file_path: &Path) -> UnifiedDiff {
    let orig_lines: Vec<&str> = original.lines().collect();
    let mod_lines: Vec<&str> = modified.lines().collect();

    let orig_header = format!("--- a/{}", file_path.display());
    let mod_header = format!("+++ b/{}", file_path.display());

    // If identical, return empty diff
    if orig_lines == mod_lines {
        return UnifiedDiff {
            file_path: file_path.to_path_buf(),
            original_header: orig_header,
            modified_header: mod_header,
            chunks: Vec::new(),
            raw_diff: String::new(),
        };
    }

    // Simple context-diff hunk generation (context = 3)
    let context_size = 3;
    let mut chunks = Vec::new();

    // Identify changed line ranges
    let mut i = 0;
    let mut j = 0;

    while i < orig_lines.len() || j < mod_lines.len() {
        if i < orig_lines.len() && j < mod_lines.len() && orig_lines[i] == mod_lines[j] {
            i += 1;
            j += 1;
            continue;
        }

        // Change detected
        let change_orig_start = i;
        let change_mod_start = j;

        // Advance to next matching sequence of at least 3 lines
        while i < orig_lines.len() || j < mod_lines.len() {
            if i < orig_lines.len() && j < mod_lines.len() && orig_lines[i] == mod_lines[j] {
                // Check if next 3 lines match
                let mut match_len = 0;
                while i + match_len < orig_lines.len()
                    && j + match_len < mod_lines.len()
                    && orig_lines[i + match_len] == mod_lines[j + match_len]
                {
                    match_len += 1;
                    if match_len >= 3 {
                        break;
                    }
                }
                if match_len >= 3 {
                    break;
                }
            }
            if i < orig_lines.len() {
                i += 1;
            }
            if j < mod_lines.len() {
                j += 1;
            }
        }

        let change_orig_end = i;
        let change_mod_end = j;

        // Context before
        let hunk_orig_start = change_orig_start.saturating_sub(context_size);
        let hunk_mod_start = change_mod_start.saturating_sub(context_size);

        // Context after
        let hunk_orig_end = (change_orig_end + context_size).min(orig_lines.len());
        let _hunk_mod_end = (change_mod_end + context_size).min(mod_lines.len());

        let mut hunk_lines = Vec::new();

        // Context before lines
        for line in &orig_lines[hunk_orig_start..change_orig_start] {
            hunk_lines.push(format!(" {}", line));
        }

        // Deleted lines
        for line in &orig_lines[change_orig_start..change_orig_end] {
            hunk_lines.push(format!("-{}", line));
        }

        // Added lines
        for line in &mod_lines[change_mod_start..change_mod_end] {
            hunk_lines.push(format!("+{}", line));
        }

        // Context after lines
        for line in &orig_lines[change_orig_end..hunk_orig_end] {
            hunk_lines.push(format!(" {}", line));
        }

        let old_lines_count = hunk_orig_end - hunk_orig_start;
        let new_lines_count = (change_mod_end - change_mod_start)
            + (hunk_orig_start..change_orig_start).len()
            + (change_orig_end..hunk_orig_end).len();

        chunks.push(DiffChunk {
            old_start: hunk_orig_start + 1, // 1-based POSIX
            old_lines: old_lines_count,
            new_start: hunk_mod_start + 1,
            new_lines: new_lines_count,
            lines: hunk_lines,
        });
    }

    let mut raw_diff = format!("{}\n{}\n", orig_header, mod_header);
    for chunk in &chunks {
        raw_diff.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            chunk.old_start, chunk.old_lines, chunk.new_start, chunk.new_lines
        ));
        for line in &chunk.lines {
            raw_diff.push_str(line);
            raw_diff.push('\n');
        }
    }

    UnifiedDiff {
        file_path: file_path.to_path_buf(),
        original_header: orig_header,
        modified_header: mod_header,
        chunks,
        raw_diff,
    }
}

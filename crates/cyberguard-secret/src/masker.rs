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

//! Credential masking and surgical redaction utilities.

/// Masks sensitive credentials to prevent secondary disclosure in logs, stdout, or SARIF.
/// Preserves first 4 characters and last 2 characters for identification, replacing the middle with `*`.
/// For short tokens, masks proportional characters.
pub fn mask_secret(raw: &str) -> String {
    let char_count = raw.chars().count();
    if char_count == 0 {
        return String::new();
    }
    if char_count <= 4 {
        return "*".repeat(char_count);
    }
    if char_count <= 6 {
        let first: String = raw.chars().take(1).collect();
        let last: String = raw.chars().skip(char_count - 1).collect();
        let middle = "*".repeat(char_count - 2);
        return format!("{}{}{}", first, middle, last);
    }

    let prefix: String = raw.chars().take(4).collect();
    let suffix: String = raw.chars().skip(char_count - 2).collect();
    let masked_middle = "*".repeat(char_count - 6);

    format!("{}{}{}", prefix, masked_middle, suffix)
}

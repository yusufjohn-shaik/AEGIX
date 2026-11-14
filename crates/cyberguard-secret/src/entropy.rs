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

//! Mathematical Shannon entropy calculations for evaluating randomness.

use std::collections::HashMap;

/// Calculates the Shannon entropy of a string in bits per character.
/// Formula: H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)
pub fn calculate_shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut frequency_map = HashMap::new();
    let mut total_chars = 0usize;

    for ch in input.chars() {
        *frequency_map.entry(ch).or_insert(0usize) += 1;
        total_chars += 1;
    }

    if total_chars == 0 {
        return 0.0;
    }

    let len_f64 = total_chars as f64;
    let mut entropy = 0.0f64;

    for &count in frequency_map.values() {
        let p = count as f64 / len_f64;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Helper function to check if a token meets or exceeds an entropy threshold.
pub fn is_high_entropy(input: &str, threshold: f64) -> bool {
    calculate_shannon_entropy(input) >= threshold
}

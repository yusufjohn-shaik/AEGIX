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

use cyberguard_secret::entropy::{calculate_shannon_entropy, is_high_entropy};

#[test]
fn test_entropy_empty_string() {
    assert_eq!(calculate_shannon_entropy(""), 0.0);
}

#[test]
fn test_entropy_single_character_repeated() {
    assert_eq!(calculate_shannon_entropy("aaaaaa"), 0.0);
    assert_eq!(calculate_shannon_entropy("0000000000"), 0.0);
}

#[test]
fn test_entropy_low_predictable_words() {
    let word_entropy = calculate_shannon_entropy("password");
    // "password" has len 8, chars: p,a,s(2),w,o,r,d -> 2.75 bits
    assert!((word_entropy - 2.75).abs() < 0.01);
    assert!(!is_high_entropy("password", 4.0));

    let admin_entropy = calculate_shannon_entropy("administrator");
    assert!(admin_entropy < 3.5);
    assert!(!is_high_entropy("administrator", 4.0));
}

#[test]
fn test_entropy_high_random_tokens() {
    // Highly diverse base64 string
    let high_b64 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let entropy = calculate_shannon_entropy(high_b64);
    assert!(entropy > 4.5, "Expected entropy > 4.5, got {}", entropy);
    assert!(is_high_entropy(high_b64, 4.5));

    // AWS Access Key format
    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    let aws_entropy = calculate_shannon_entropy(aws_key);
    assert!(
        aws_entropy > 3.0,
        "Expected entropy > 3.0, got {}",
        aws_entropy
    );
}

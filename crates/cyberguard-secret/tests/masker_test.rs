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

use cyberguard_secret::masker::mask_secret;

#[test]
fn test_mask_standard_aws_key() {
    let raw = "AKIAIOSFODNN7EXAMPLE";
    let masked = mask_secret(raw);
    assert_eq!(masked, "AKIA**************LE");
    assert_eq!(masked.len(), raw.len());
}

#[test]
fn test_mask_github_token() {
    let raw = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    let masked = mask_secret(raw);
    assert!(masked.starts_with("ghp_"));
    assert!(masked.ends_with("yz"));
    assert_eq!(masked.len(), raw.len());
    assert_eq!(&masked[4..raw.len() - 2], "*".repeat(raw.len() - 6));
}

#[test]
fn test_mask_short_strings() {
    assert_eq!(mask_secret(""), "");
    assert_eq!(mask_secret("a"), "*");
    assert_eq!(mask_secret("ab"), "**");
    assert_eq!(mask_secret("abcd"), "****");
    assert_eq!(mask_secret("abcde"), "a***e");
    assert_eq!(mask_secret("abcdef"), "a****f");
    assert_eq!(mask_secret("abcdefg"), "abcd*fg");
}

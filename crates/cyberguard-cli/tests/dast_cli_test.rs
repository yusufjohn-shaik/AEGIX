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

use cyberguard_dast::{DastEngine, DastScanner, DastTarget};
use cyberguard_net::{verify_scope_hmac, ScopeGate};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn test_dast_with_scope_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("network-scope")
        .join(".security-scope.yaml");

    let gate = ScopeGate::from_file(&fixture_path).expect("Scope file must exist and parse");

    // Verify HMAC Proof-of-Authorization
    let secret_key = b"fixture-secret-key-2026";
    assert!(
        verify_scope_hmac(&gate.scope, secret_key).is_ok(),
        "Scope HMAC signature must verify cleanly"
    );

    // Spawn mock HTTP server on localhost
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let body = "CyberGuard Web Test Server";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        }
    });

    let target_url = Url::parse(&format!("http://127.0.0.1:{}", port)).unwrap();
    let target = DastTarget::new(target_url);
    let engine = DastEngine::new().with_timeout_ms(2000);

    let report = engine
        .scan(&target, &gate)
        .await
        .expect("DAST scan should succeed");
    assert!(report.tested_endpoints_count > 0);
}

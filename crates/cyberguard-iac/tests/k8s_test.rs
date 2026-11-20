use cyberguard_iac::k8s::DefaultK8sAuditor;
use cyberguard_iac::models::K8sManifest;
use cyberguard_iac::traits::K8sAuditor;

#[test]
fn test_k8s_audits_vulnerable_pod() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: app
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: root-container
      image: ubuntu:latest
      securityContext:
        privileged: true
        runAsUser: 0
        runAsNonRoot: false
        capabilities:
          add:
            - SYS_ADMIN
"#;

    let manifest: K8sManifest = serde_yaml::from_str(yaml).unwrap();
    let auditor = DefaultK8sAuditor;
    let findings = auditor.audit_manifest(&manifest, "pod.yaml", yaml).unwrap();

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-IAC-001"),
        "Expected CG-IAC-001 (Privileged)"
    );
    assert!(
        rule_ids.contains(&"CG-IAC-002"),
        "Expected CG-IAC-002 (Run as root)"
    );
    assert!(
        rule_ids.contains(&"CG-IAC-003"),
        "Expected CG-IAC-003 (Host namespaces)"
    );
    assert!(
        rule_ids.contains(&"CG-IAC-004"),
        "Expected CG-IAC-004 (Capabilities)"
    );
    assert!(
        rule_ids.contains(&"CG-IAC-005"),
        "Expected CG-IAC-005 (Missing limits)"
    );
    assert!(
        rule_ids.contains(&"CG-IAC-006"),
        "Expected CG-IAC-006 (Writable root)"
    );
}

#[test]
fn test_k8s_system_workload_exemption() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cilium-cni-daemon
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
    - name: cilium-agent
      image: cilium/cilium:v1.14
      securityContext:
        privileged: true
"#;

    let manifest: K8sManifest = serde_yaml::from_str(yaml).unwrap();
    let auditor = DefaultK8sAuditor;
    let findings = auditor
        .audit_manifest(&manifest, "cilium.yaml", yaml)
        .unwrap();

    // System workload should be exempted from CG-IAC-001 and CG-IAC-003 hostNetwork
    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"CG-IAC-001"),
        "Expected system workload to exempt CG-IAC-001"
    );
    assert!(
        !rule_ids.contains(&"CG-IAC-003"),
        "Expected system workload to exempt CG-IAC-003 hostNetwork"
    );
}

#[test]
fn test_k8s_safe_hardened_deployment() {
    let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-deployment
  namespace: prod
spec:
  template:
    spec:
      hostPID: false
      hostNetwork: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: app
          image: app:v1
          securityContext:
            privileged: false
            runAsNonRoot: true
            runAsUser: 10001
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              cpu: "100m"
              memory: "128Mi"
"#;

    let manifest: K8sManifest = serde_yaml::from_str(yaml).unwrap();
    let auditor = DefaultK8sAuditor;
    let findings = auditor
        .audit_manifest(&manifest, "deploy.yaml", yaml)
        .unwrap();

    assert_eq!(
        findings.len(),
        0,
        "Hardened deployment should have 0 findings"
    );
}

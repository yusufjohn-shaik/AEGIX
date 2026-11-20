use cyberguard_iac::models::IacFormat;
use cyberguard_iac::parser::IacParser;
use std::path::PathBuf;

#[test]
fn test_detect_format() {
    assert_eq!(
        IacParser::detect_format("", &PathBuf::from("main.tf")).unwrap(),
        IacFormat::TerraformHcl
    );
    assert_eq!(
        IacParser::detect_format("", &PathBuf::from("deploy.yaml")).unwrap(),
        IacFormat::KubernetesYaml
    );
    assert_eq!(
        IacParser::detect_format("", &PathBuf::from("service.yml")).unwrap(),
        IacFormat::KubernetesYaml
    );
    assert_eq!(
        IacParser::detect_format("", &PathBuf::from("resources.tf.json")).unwrap(),
        IacFormat::TerraformJson
    );
}

#[test]
fn test_multi_document_k8s_yaml_parsing() {
    let yaml = r#"
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  ports:
    - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: nginx
      image: nginx:alpine
"#;

    let docs = IacParser::parse_str(yaml, &PathBuf::from("multi.yaml")).unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].document_index, 0);
    assert_eq!(docs[1].document_index, 1);
}

#[test]
fn test_unrendered_helm_graceful_skip() {
    let helm_yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "mychart.fullname" . }}
spec:
  replicas: 1
"#;

    let docs =
        IacParser::parse_str(helm_yaml, &PathBuf::from("chart/templates/deployment.yaml")).unwrap();
    assert!(docs.is_empty() || docs.len() == 1);
}

#[test]
fn test_terraform_hcl_block_parsing() {
    let hcl = r#"
resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Web Security Group"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "region" {
  default     = "us-east-1"
  description = "AWS deployment region"
}

locals {
  app_env = "production"
}
"#;

    let docs = IacParser::parse_str(hcl, &PathBuf::from("network.tf")).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].resources.len(), 3);
}

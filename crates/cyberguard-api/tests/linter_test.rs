use cyberguard_api::linter::DefaultApiLinter;
use cyberguard_api::parser::parse_spec_str;
use cyberguard_api::traits::ApiLinter;
use cyberguard_core::sarif::SarifLevel;

const VULNERABLE_API_SPEC: &str = r#"
openapi: 3.0.0
info:
  title: Insecure API
  version: 1.0.0
servers:
  - url: http://api.production.example.com
  - url: http://localhost:3000
paths:
  /health:
    get:
      summary: Health check (public exempt)
      responses:
        '200':
          description: ok
  /api/v1/users:
    get:
      summary: Unbounded users list
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/User'
    post:
      summary: Register user with mass assignment risk
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                role:
                  type: string
                  readOnly: false
                password:
                  type: string
      responses:
        '200':
          description: User created with password leaked in response
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: integer
                  password:
                    type: string
                    writeOnly: false
  /api/v1/users/{userId}:
    get:
      summary: Unauthenticated BOLA access
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: User details
  /admin/system/restart:
    post:
      summary: Unprotected administrative action (BFLA)
      responses:
        '200':
          description: Rebooted
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
"#;

#[test]
fn test_linter_all_rules_detection() {
    let spec = parse_spec_str(VULNERABLE_API_SPEC, None).unwrap();
    let linter = DefaultApiLinter::new();
    let findings = linter.lint(&spec, "insecure_api.yaml");

    // 1. CG-API-002: Insecure Plaintext Server URL (http://api.production.example.com, but NOT http://localhost:3000)
    let url_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-002")
        .collect();
    assert_eq!(url_findings.len(), 1);
    assert!(url_findings[0]
        .description
        .contains("http://api.production.example.com"));

    // 2. CG-API-001: Missing Operation Security (triggered on unauthenticated routes, but NOT /health)
    let unauth_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-001")
        .collect();
    assert!(!unauth_findings.is_empty());
    assert!(!unauth_findings.iter().any(|f| f.path == "/health"));

    // 3. CG-API-003: Unauthenticated Object ID Access (BOLA) on /api/v1/users/{userId}
    let bola_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-003")
        .collect();
    assert_eq!(bola_findings.len(), 1);
    assert_eq!(bola_findings[0].path, "/api/v1/users/{userId}");

    // 4. CG-API-004: Mass Assignment on POST /api/v1/users (role property)
    let mass_assign: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-004")
        .collect();
    assert_eq!(mass_assign.len(), 1);
    assert_eq!(mass_assign[0].path, "/api/v1/users");
    assert!(mass_assign[0].description.contains("role"));

    // 5. CG-API-005: Unbounded Collection Pagination on GET /api/v1/users
    let pagination_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-005")
        .collect();
    assert_eq!(pagination_findings.len(), 1);
    assert_eq!(pagination_findings[0].path, "/api/v1/users");

    // 6. CG-API-006: Excessive Data Exposure (password in response 200 without writeOnly)
    let leak_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-006")
        .collect();
    assert_eq!(leak_findings.len(), 1);
    assert!(leak_findings[0].description.contains("password"));

    // 7. CG-API-007: Missing Admin Route Authentication on /admin/system/restart
    let bfla_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-007")
        .collect();
    assert_eq!(bfla_findings.len(), 1);
    assert_eq!(bfla_findings[0].severity, SarifLevel::Error);
    assert_eq!(bfla_findings[0].path, "/admin/system/restart");
}

#[test]
fn test_linter_calibrated_exemptions_zero_false_positives() {
    let secure_spec = r#"
openapi: 3.0.0
info:
  title: Hardened Production API
  version: 1.0.0
servers:
  - url: https://api.corp.example.com
paths:
  /health:
    get:
      summary: Health check
      responses:
        '200':
          description: ok
  /api/v1/users:
    get:
      summary: Paged users
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
      responses:
        '200':
          description: List
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
      security:
        - bearerAuth: []
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                role:
                  type: string
                  readOnly: true
      responses:
        '200':
          description: Created
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: integer
                  password:
                    type: string
                    writeOnly: true
      security:
        - bearerAuth: []
  /admin/roles:
    post:
      summary: Admin endpoint legitimately setting role
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                role:
                  type: string
      responses:
        '200':
          description: Role created
      security:
        - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
"#;

    let spec = parse_spec_str(secure_spec, None).unwrap();
    let linter = DefaultApiLinter::new();
    let findings = linter.lint(&spec, "hardened.yaml");

    // All rules should pass with ZERO findings due to calibrated exemptions!
    assert_eq!(
        findings.len(),
        0,
        "Expected 0 findings on hardened spec, found: {:?}",
        findings
    );
}

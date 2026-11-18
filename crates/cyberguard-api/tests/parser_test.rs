use cyberguard_api::error::ApiError;
use cyberguard_api::models::SpecVersion;
use cyberguard_api::parser::parse_spec_str;

const OPENAPI_30_SPEC: &str = r#"
openapi: 3.0.3
info:
  title: Sample Pet Store API
  version: 1.0.0
servers:
  - url: https://api.petstore.example.com/v1
  - url: http://localhost:8080/v1
paths:
  /pets:
    get:
      summary: List all pets
      operationId: listPets
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
            format: int32
      responses:
        '200':
          description: A paged array of pets
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Pet'
      security:
        - bearerAuth: []
  /pets/{petId}:
    get:
      summary: Info for a specific pet
      operationId: showPetById
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Expected response to a valid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    Pet:
      type: object
      required:
        - id
        - name
      properties:
        id:
          type: integer
          format: int64
        name:
          type: string
"#;

const SWAGGER_20_SPEC: &str = r#"
swagger: "2.0"
info:
  title: Legacy Petstore Swagger
  version: 2.0.0
host: api.swaggerpetstore.com
basePath: /v2
schemes:
  - https
paths:
  /users:
    get:
      summary: Get users
      parameters:
        - name: page
          in: query
          type: integer
      responses:
        200:
          description: List of users
          schema:
            type: array
            items:
              $ref: '#/definitions/User'
    post:
      summary: Create user
      parameters:
        - name: body
          in: body
          required: true
          schema:
            $ref: '#/definitions/User'
      responses:
        201:
          description: Created
definitions:
  User:
    type: object
    properties:
      id:
        type: integer
      username:
        type: string
"#;

const RECURSIVE_SCHEMA_SPEC: &str = r#"
openapi: 3.0.0
info:
  title: Recursive Tree Node API
  version: 1.0.0
paths:
  /tree:
    get:
      responses:
        '200':
          description: Node hierarchy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TreeNode'
components:
  schemas:
    TreeNode:
      type: object
      properties:
        id:
          type: string
        child:
          $ref: '#/components/schemas/TreeNode'
"#;

#[test]
fn test_parse_openapi_30_success() {
    let spec = parse_spec_str(OPENAPI_30_SPEC, None).expect("Should parse OpenAPI 3.0 spec");
    assert_eq!(spec.version, SpecVersion::OpenApi30);
    assert_eq!(spec.title, "Sample Pet Store API");
    assert_eq!(spec.servers.len(), 2);
    assert_eq!(spec.operations.len(), 2);

    let list_pets = spec.operations.iter().find(|o| o.path == "/pets").unwrap();
    assert_eq!(list_pets.method, "GET");
    assert_eq!(list_pets.parameters.len(), 1);
    assert_eq!(list_pets.parameters[0].name, "limit");
    assert!(!list_pets.security.is_empty());
}

#[test]
fn test_parse_swagger_20_success() {
    let spec = parse_spec_str(SWAGGER_20_SPEC, None).expect("Should parse Swagger 2.0 spec");
    assert_eq!(spec.version, SpecVersion::Swagger2);
    assert_eq!(spec.title, "Legacy Petstore Swagger");
    assert_eq!(spec.servers, vec!["https://api.swaggerpetstore.com/v2"]);
    assert_eq!(spec.operations.len(), 2);

    let post_users = spec
        .operations
        .iter()
        .find(|o| o.path == "/users" && o.method == "POST")
        .unwrap();
    assert!(post_users.request_body.is_some());
    let req_body = post_users.request_body.as_ref().unwrap();
    assert!(req_body.content_types.contains_key("application/json"));
}

#[test]
fn test_recursive_schema_cycle_tracking_graceful() {
    let spec = parse_spec_str(RECURSIVE_SCHEMA_SPEC, None)
        .expect("Recursive schemas must not cause stack overflow or parse failure");
    assert_eq!(spec.operations.len(), 1);
    let op = &spec.operations[0];
    let resp = op.responses.get("200").unwrap();
    let schema = resp.content_types.get("application/json").unwrap();
    assert_eq!(schema.schema_type.as_deref(), Some("object"));
    assert!(schema.properties.contains_key("child"));
    let child = schema.properties.get("child").unwrap();
    assert_eq!(
        child.ref_path.as_deref(),
        Some("#/components/schemas/TreeNode")
    );
}

#[test]
fn test_external_network_ref_forbidden() {
    let malicious_spec = r#"
openapi: 3.0.0
info:
  title: SSRF Exploit
  version: 1.0.0
paths:
  /test:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: 'http://169.254.169.254/latest/meta-data/'
"#;

    let res = parse_spec_str(malicious_spec, None);
    assert!(res.is_err());
    match res.err().unwrap() {
        ApiError::ExternalNetworkRefForbidden(ref_uri) => {
            assert!(ref_uri.contains("169.254.169.254"));
        }
        other => panic!("Expected ExternalNetworkRefForbidden, got: {:?}", other),
    }
}

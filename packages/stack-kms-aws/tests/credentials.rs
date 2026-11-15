//! The workload identity credential providers and the default chain,
//! against recorded responses of STS, the container endpoint and IMDS.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stack_kms::BackendErrorKind;
use stack_kms_aws::credentials::{
    CachedCredentials, CredentialsProvider, DefaultCredentialsSource, EcsCredentials, EnvLookup,
    ImdsCredentials, WebIdentityCredentials,
};
use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};
use web_time::UNIX_EPOCH;

/// A transport that answers from a script and keeps every request.
#[derive(Clone, Debug, Default)]
struct Scripted {
    responses: Arc<Mutex<VecDeque<VendorResponse>>>,
    sent: Arc<Mutex<Vec<VendorRequest>>>,
}

impl Scripted {
    fn answering(responses: impl IntoIterator<Item = VendorResponse>) -> Self {
        let scripted = Self::default();
        scripted.responses.lock().unwrap().extend(responses);
        scripted
    }

    fn sent(&self) -> Vec<VendorRequest> {
        self.sent.lock().unwrap().clone()
    }
}

impl VendorTransport for Scripted {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        self.sent.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| TransportError("connection refused".into()))
    }

    async fn sleep(&self, _duration: Duration) {}
}

fn env(pairs: &[(&str, &str)]) -> EnvLookup {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Arc::new(move |name| map.get(name).cloned())
}

/// A file holding `contents`, removed on drop.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, contents: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("stack-kms-aws-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An STS `AssumeRoleWithWebIdentity` response, as STS sends it.
const STS_RESPONSE: &str = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>system:serviceaccount:default:app</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::111122223333:assumed-role/app/stack-kms-aws</Arn>
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:stack-kms-aws</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>FwoGZXIvYXdzEXAMPLE&amp;TOKEN</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2026-11-05T13:00:00Z</Expiration>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
    <SourceIdentity>app</SourceIdentity>
    <Provider>arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

/// The JSON credentials the container endpoint and IMDS return.
const JSON_CREDENTIALS: &str = r#"{
  "Code": "Success",
  "LastUpdated": "2026-11-05T11:55:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAJSONEXAMPLE",
  "SecretAccessKey": "json-secret",
  "Token": "json-token",
  "Expiration": "2026-11-05T18:00:00Z"
}"#;

fn ok(body: &str) -> VendorResponse {
    VendorResponse::new(200, body.as_bytes().to_vec())
}

#[tokio::test]
async fn irsa_assumes_the_role_with_the_token_file() {
    let token = TempFile::new("irsa-token", "eyJhbGciOiJSUzI1NiJ9.token\n");
    let transport = Scripted::answering([ok(STS_RESPONSE)]);
    let provider = WebIdentityCredentials::from_env_lookup(
        &env(&[
            ("AWS_WEB_IDENTITY_TOKEN_FILE", token.path()),
            ("AWS_ROLE_ARN", "arn:aws:iam::111122223333:role/app"),
            ("AWS_ROLE_SESSION_NAME", "my session"),
        ]),
        transport.clone(),
        Some("ap-southeast-2"),
    )
    .unwrap();
    let credentials = provider.credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAIOSFODNN7EXAMPLE");
    assert_eq!(
        credentials.secret_access_key(),
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
    );
    assert_eq!(
        credentials.session_token(),
        Some("FwoGZXIvYXdzEXAMPLE&TOKEN")
    );
    assert_eq!(
        credentials.expires_at(),
        Some(UNIX_EPOCH + Duration::from_secs(1_793_883_600))
    );

    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, "https://sts.ap-southeast-2.amazonaws.com/");
    assert_eq!(
        sent[0].header_value("content-type"),
        Some("application/x-www-form-urlencoded; charset=utf-8")
    );
    assert!(
        sent[0].header_value("authorization").is_none(),
        "AssumeRoleWithWebIdentity is not signed"
    );
    assert_eq!(
        std::str::from_utf8(&sent[0].body).unwrap(),
        "Action=AssumeRoleWithWebIdentity\
         &RoleArn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fapp\
         &RoleSessionName=my%20session&Version=2011-06-15\
         &WebIdentityToken=eyJhbGciOiJSUzI1NiJ9.token"
    );
}

#[tokio::test]
async fn irsa_fails_cleanly() {
    assert!(WebIdentityCredentials::from_env_lookup(
        &env(&[("AWS_ROLE_ARN", "arn")]),
        Scripted::default(),
        None
    )
    .is_none());

    let provider = WebIdentityCredentials::new(
        Scripted::default(),
        "arn:aws:iam::111122223333:role/app",
        "/no/such/token/file",
        None,
    );
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);

    let token = TempFile::new("irsa-denied", "token");
    let denied = VendorResponse::new(
        403,
        b"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
          <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error></ErrorResponse>"
            .to_vec(),
    );
    let transport = Scripted::answering([denied]);
    let provider = WebIdentityCredentials::new(transport.clone(), "arn", token.path(), None)
        .with_sts_endpoint("https://sts.example/");
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert_eq!(transport.sent()[0].url, "https://sts.example/");

    let provider = WebIdentityCredentials::new(Scripted::default(), "arn", token.path(), None);
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::Unavailable);
}

#[tokio::test]
async fn the_container_endpoint_gives_credentials() {
    let transport = Scripted::answering([ok(JSON_CREDENTIALS)]);
    let provider = EcsCredentials::from_env_lookup(
        &env(&[(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/5c4f4e3a",
        )]),
        transport.clone(),
    )
    .unwrap()
    .unwrap();
    let credentials = provider.credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAJSONEXAMPLE");
    assert_eq!(credentials.session_token(), Some("json-token"));
    let sent = transport.sent();
    assert_eq!(sent[0].method, "GET");
    assert_eq!(sent[0].url, "http://169.254.170.2/v2/credentials/5c4f4e3a");
    assert!(sent[0].header_value("authorization").is_none());
}

#[tokio::test]
async fn eks_pod_identity_sends_the_token_from_its_file() {
    let token = TempFile::new("pod-identity", "pod-identity-token\n");
    let transport = Scripted::answering([ok(JSON_CREDENTIALS)]);
    let provider = EcsCredentials::from_env_lookup(
        &env(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "http://169.254.170.23/v1/credentials",
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", token.path()),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "ignored"),
        ]),
        transport.clone(),
    )
    .unwrap()
    .unwrap();
    provider.credentials().await.unwrap();
    let sent = transport.sent();
    assert_eq!(sent[0].url, "http://169.254.170.23/v1/credentials");
    assert_eq!(
        sent[0].header_value("authorization"),
        Some("pod-identity-token")
    );

    let transport = Scripted::answering([ok(JSON_CREDENTIALS)]);
    let provider = EcsCredentials::from_env_lookup(
        &env(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "https://creds.example/",
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "static-token"),
        ]),
        transport.clone(),
    )
    .unwrap()
    .unwrap();
    provider.credentials().await.unwrap();
    assert_eq!(
        transport.sent()[0].header_value("authorization"),
        Some("static-token")
    );

    assert!(
        EcsCredentials::from_env_lookup(&env(&[]), Scripted::default())
            .unwrap()
            .is_none()
    );
    assert!(EcsCredentials::from_env_lookup(
        &env(&[(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://evil.example/creds"
        )]),
        Scripted::default()
    )
    .is_err());
}

#[tokio::test]
async fn imds_uses_a_session_token() {
    let transport = Scripted::answering([
        ok("imds-session-token"),
        ok("app-instance-role\n"),
        ok(JSON_CREDENTIALS),
    ]);
    let provider = ImdsCredentials::from_env_lookup(&env(&[]), transport.clone()).unwrap();
    let credentials = provider.credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAJSONEXAMPLE");
    assert_eq!(
        credentials.expires_at(),
        Some(UNIX_EPOCH + Duration::from_secs(1_793_901_600))
    );
    let sent = transport.sent();
    assert_eq!(sent.len(), 3);
    assert_eq!(
        (sent[0].method.as_str(), sent[0].url.as_str()),
        ("PUT", "http://169.254.169.254/latest/api/token")
    );
    assert_eq!(
        sent[0].header_value("x-aws-ec2-metadata-token-ttl-seconds"),
        Some("21600")
    );
    assert_eq!(
        sent[1].url,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    );
    assert_eq!(
        sent[2].url,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-instance-role"
    );
    for request in &sent[1..] {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.header_value("x-aws-ec2-metadata-token"),
            Some("imds-session-token")
        );
    }
}

#[tokio::test]
async fn imds_can_be_moved_or_disabled() {
    assert!(ImdsCredentials::from_env_lookup(
        &env(&[("AWS_EC2_METADATA_DISABLED", "TRUE")]),
        Scripted::default()
    )
    .is_none());
    let transport = Scripted::answering([ok("t"), ok("role"), ok(JSON_CREDENTIALS)]);
    let provider = ImdsCredentials::from_env_lookup(
        &env(&[(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
            "http://[fd00:ec2::254]/",
        )]),
        transport.clone(),
    )
    .unwrap();
    provider.credentials().await.unwrap();
    assert_eq!(
        transport.sent()[0].url,
        "http://[fd00:ec2::254]/latest/api/token"
    );
}

#[tokio::test]
async fn imds_failures_map_to_kinds() {
    // Off EC2: no answer.
    let provider = ImdsCredentials::new(Scripted::default(), "http://169.254.169.254");
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    // No instance profile: an empty role list, or a 404.
    let provider = ImdsCredentials::new(Scripted::answering([ok("t"), ok("")]), "http://imds");
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    let provider = ImdsCredentials::new(
        Scripted::answering([ok("t"), VendorResponse::new(404, vec![])]),
        "http://imds",
    );
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::NotFound);
    // IMDSv1 only (token refused).
    let provider = ImdsCredentials::new(
        Scripted::answering([VendorResponse::new(403, vec![])]),
        "http://imds",
    );
    let error = provider.credentials().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
}

#[test]
fn the_chain_picks_the_source_the_environment_names() {
    let pick = |pairs: &[(&str, &str)]| {
        DefaultCredentialsSource::from_env_lookup(&env(pairs), Scripted::default(), None)
    };
    assert!(matches!(
        pick(&[
            ("AWS_ACCESS_KEY_ID", "AKID"),
            ("AWS_SECRET_ACCESS_KEY", "s"),
            ("AWS_ROLE_ARN", "arn"),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"),
        ]),
        Ok(DefaultCredentialsSource::Static(_))
    ));
    assert!(matches!(
        pick(&[
            ("AWS_ROLE_ARN", "arn"),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"),
            ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2"),
        ]),
        Ok(DefaultCredentialsSource::WebIdentity(_))
    ));
    assert!(matches!(
        pick(&[("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2")]),
        Ok(DefaultCredentialsSource::Ecs(_))
    ));
    assert!(matches!(pick(&[]), Ok(DefaultCredentialsSource::Imds(_))));
    let error = pick(&[("AWS_EC2_METADATA_DISABLED", "true")]).unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(pick(&[("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://evil.example/")]).is_err());
}

#[tokio::test]
async fn the_cached_chain_fetches_once_until_near_expiry() {
    let transport = Scripted::answering([ok("t"), ok("role"), ok(JSON_CREDENTIALS)]);
    let source =
        DefaultCredentialsSource::from_env_lookup(&env(&[]), transport.clone(), None).unwrap();
    // 2026-11-05T12:00:00Z; the credentials expire at 18:00.
    let cache = CachedCredentials::new(source)
        .with_clock(Arc::new(|| UNIX_EPOCH + Duration::from_secs(1_793_880_000)));
    for _ in 0..3 {
        assert_eq!(
            cache.credentials().await.unwrap().access_key_id(),
            "ASIAJSONEXAMPLE"
        );
    }
    assert_eq!(
        transport.sent().len(),
        3,
        "one IMDS fetch: token, role, credentials"
    );
}

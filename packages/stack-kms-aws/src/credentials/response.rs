//! Parsing the credential responses of STS, the container endpoint and
//! IMDS.

use serde::Deserialize;
use stack_kms::BackendErrorKind;
use stack_kms_vendor::{classify_status, VendorResponse};
use zeroize::Zeroizing;

use super::{Credentials, CredentialsError};
use crate::time::parse_rfc3339;

/// The JSON credentials of the container endpoint and IMDS.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct JsonCredentials {
    code: Option<String>,
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    expiration: Option<String>,
}

/// The failure for a response that is not a success, from `source`.
pub(super) fn status_failure(source: &str, response: &VendorResponse) -> CredentialsError {
    // A 400 from a credential source is a refused request
    // (`classify_status`).
    let kind = classify_status(response.status).unwrap_or(BackendErrorKind::Unavailable);
    CredentialsError::new(kind, format!("{source} returned HTTP {}", response.status))
}

/// Parse the JSON credentials the container endpoint and IMDS return.
pub(super) fn json_credentials(
    source: &str,
    response: &VendorResponse,
) -> Result<Credentials, CredentialsError> {
    if classify_status(response.status).is_some() {
        return Err(status_failure(source, response));
    }
    let parsed: JsonCredentials = serde_json::from_slice(&response.body)
        .map_err(|_| CredentialsError::unavailable(format!("{source} returned invalid JSON")))?;
    // Move the secrets into wiping containers at once.
    let secret = Zeroizing::new(parsed.secret_access_key);
    let token = parsed.token.map(Zeroizing::new);
    if let Some(code) = parsed.code.as_deref() {
        if code != "Success" {
            return Err(CredentialsError::access_denied(format!(
                "{source} returned the code {code:?}"
            )));
        }
    }
    let mut credentials = Credentials {
        access_key_id: parsed.access_key_id,
        secret_access_key: secret,
        session_token: token,
        expires_at: None,
    };
    if let Some(expiration) = parsed.expiration.as_deref() {
        credentials.expires_at = Some(parse_rfc3339(expiration).ok_or_else(|| {
            CredentialsError::unavailable(format!("{source} returned an invalid expiry time"))
        })?);
    }
    Ok(credentials)
}

/// The text of the first `<tag>…</tag>` element in `xml`, with the five
/// XML entities decoded.
pub(super) fn xml_text(xml: &str, tag: &str) -> Option<Zeroizing<String>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    let raw = &xml[start..end];
    Some(Zeroizing::new(
        raw.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    ))
}

/// Parse an STS `AssumeRole*` response: the credentials, or the STS error.
pub(super) fn sts_credentials(response: &VendorResponse) -> Result<Credentials, CredentialsError> {
    let xml = std::str::from_utf8(&response.body)
        .map_err(|_| CredentialsError::unavailable("STS returned a body that is not UTF-8"))?;
    if classify_status(response.status).is_some() {
        let code = xml_text(xml, "Code");
        let code = code.as_deref().map(String::as_str).unwrap_or("");
        let kind = match code {
            "Throttling" | "ThrottlingException" | "RequestLimitExceeded" => {
                BackendErrorKind::Throttled
            }
            "IDPCommunicationError" | "ServiceUnavailable" | "InternalFailure" => {
                BackendErrorKind::Unavailable
            }
            _ => return Err(status_failure(&format!("STS ({code})"), response)),
        };
        return Err(CredentialsError::new(
            kind,
            format!("STS returned HTTP {} ({code})", response.status),
        ));
    }
    let field = |tag: &str| {
        xml_text(xml, tag)
            .ok_or_else(|| CredentialsError::unavailable(format!("the STS response has no {tag}")))
    };
    let access_key_id = field("AccessKeyId")?;
    let expiration = field("Expiration")?;
    Ok(Credentials {
        access_key_id: access_key_id.to_string(),
        secret_access_key: field("SecretAccessKey")?,
        session_token: Some(field("SessionToken")?),
        expires_at: Some(
            parse_rfc3339(&expiration).ok_or_else(|| {
                CredentialsError::unavailable("STS returned an invalid expiry time")
            })?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use web_time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn json_credentials_parse() {
        let response = VendorResponse::new(
            200,
            br#"{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA1","SecretAccessKey":"s","Token":"t","Expiration":"2015-08-30T12:36:00Z"}"#.to_vec(),
        );
        let credentials = json_credentials("IMDS", &response).unwrap();
        assert_eq!(credentials.access_key_id(), "ASIA1");
        assert_eq!(credentials.secret_access_key(), "s");
        assert_eq!(credentials.session_token(), Some("t"));
        assert_eq!(
            credentials.expires_at(),
            Some(UNIX_EPOCH + Duration::from_secs(1_440_938_160))
        );
    }

    #[test]
    fn json_credentials_refuse_failures() {
        let failed = br#"{"Code":"Failed","AccessKeyId":"","SecretAccessKey":""}"#.to_vec();
        let error = json_credentials("IMDS", &VendorResponse::new(200, failed)).unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
        let error =
            json_credentials("IMDS", &VendorResponse::new(200, b"not json".to_vec())).unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
        let bad_time =
            br#"{"AccessKeyId":"a","SecretAccessKey":"s","Expiration":"tomorrow"}"#.to_vec();
        let error = json_credentials("IMDS", &VendorResponse::new(200, bad_time)).unwrap_err();
        assert!(error.to_string().contains("expiry"));
        for (status, kind) in [
            (404, BackendErrorKind::NotFound),
            (401, BackendErrorKind::AccessDenied),
            (400, BackendErrorKind::AccessDenied),
            (500, BackendErrorKind::Unavailable),
            (429, BackendErrorKind::Throttled),
        ] {
            let error = json_credentials("ECS", &VendorResponse::new(status, vec![])).unwrap_err();
            assert_eq!(error.kind(), kind, "{status}");
        }
    }

    #[test]
    fn xml_text_decodes_entities() {
        assert_eq!(
            xml_text("<a><B>x&amp;y&lt;&gt;&quot;&apos;</B></a>", "B")
                .unwrap()
                .as_str(),
            "x&y<>\"'"
        );
        assert!(xml_text("<B>x", "B").is_none());
        assert!(xml_text("", "B").is_none());
    }

    #[test]
    fn sts_errors_map_to_kinds() {
        for (status, code, kind) in [
            (400, "Throttling", BackendErrorKind::Throttled),
            (400, "IDPCommunicationError", BackendErrorKind::Unavailable),
            (403, "AccessDenied", BackendErrorKind::AccessDenied),
            (400, "InvalidIdentityToken", BackendErrorKind::AccessDenied),
            (400, "ExpiredTokenException", BackendErrorKind::AccessDenied),
            (503, "Other", BackendErrorKind::Unavailable),
        ] {
            let body = format!(
                "<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code><Message>m</Message></Error></ErrorResponse>"
            );
            let error =
                sts_credentials(&VendorResponse::new(status, body.into_bytes())).unwrap_err();
            assert_eq!(error.kind(), kind, "{code}");
        }
        let error = sts_credentials(&VendorResponse::new(200, b"<x/>".to_vec())).unwrap_err();
        assert!(error.to_string().contains("AccessKeyId"));
        let error = sts_credentials(&VendorResponse::new(200, vec![0xff])).unwrap_err();
        assert!(error.to_string().contains("UTF-8"));
    }
}

use std::fmt;
use std::str::FromStr;

use crate::SecretToken;

/// The prefix that all CipherStash access keys start with.
const ACCESS_KEY_PREFIX: &str = "CSAK";

/// A CipherStash access key.
///
/// Access keys have the format `CSAK<key_id>.<key_secret>` and are used to
/// authenticate with the CipherStash Token Service (CTS).
///
/// The inner value is stored as a [`SecretToken`], so it is zeroized on drop
/// and hidden from debug output.
///
/// # Parsing
///
/// ```
/// use stack_auth::AccessKey;
///
/// let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
/// ```
///
/// Invalid keys are rejected:
///
/// ```
/// use stack_auth::AccessKey;
///
/// assert!("not-a-valid-key".parse::<AccessKey>().is_err());
/// assert!("CSAKmissing-dot".parse::<AccessKey>().is_err());
/// assert!("CSAK.no-key-id".parse::<AccessKey>().is_err());
/// assert!("CSAKno-secret.".parse::<AccessKey>().is_err());
/// ```
pub struct AccessKey(SecretToken);

impl AccessKey {
    /// Expose the underlying [`SecretToken`].
    pub(crate) fn into_secret_token(self) -> SecretToken {
        self.0
    }
}

impl FromStr for AccessKey {
    type Err = InvalidAccessKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix(ACCESS_KEY_PREFIX)
            .ok_or(InvalidAccessKey::MissingPrefix)?;

        let (id, secret) = rest.split_once('.').ok_or(InvalidAccessKey::MissingDot)?;

        if id.is_empty() {
            return Err(InvalidAccessKey::EmptyKeyId);
        }
        if secret.is_empty() {
            return Err(InvalidAccessKey::EmptySecret);
        }

        Ok(Self(SecretToken::new(s)))
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessKey(***)")
    }
}

/// Error returned when parsing an invalid access key string.
#[derive(Debug, thiserror::Error)]
pub enum InvalidAccessKey {
    /// The string does not start with the `CSAK` prefix.
    #[error("access key must start with \"{ACCESS_KEY_PREFIX}\"")]
    MissingPrefix,
    /// No `.` separator found between key ID and secret.
    #[error("access key must contain a \".\" separator")]
    MissingDot,
    /// The key ID portion (before the `.`) is empty.
    #[error("access key ID must not be empty")]
    EmptyKeyId,
    /// The secret portion (after the `.`) is empty.
    #[error("access key secret must not be empty")]
    EmptySecret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key() {
        let key: AccessKey =
            "CSAKT4ZMT2AUPXI7TCD2.ZAQRW2BWXP3Z6SHR4YG2TP3N35LLU46ZAWLR3BL5WUR4IIGA"
                .parse()
                .unwrap();
        assert_eq!(
            key.0.as_str(),
            "CSAKT4ZMT2AUPXI7TCD2.ZAQRW2BWXP3Z6SHR4YG2TP3N35LLU46ZAWLR3BL5WUR4IIGA"
        );
    }

    #[test]
    fn missing_prefix() {
        let err = "key_id.key_secret".parse::<AccessKey>().unwrap_err();
        assert!(matches!(err, InvalidAccessKey::MissingPrefix));
    }

    #[test]
    fn missing_dot() {
        let err = "CSAKnodot".parse::<AccessKey>().unwrap_err();
        assert!(matches!(err, InvalidAccessKey::MissingDot));
    }

    #[test]
    fn empty_key_id() {
        let err = "CSAK.secret".parse::<AccessKey>().unwrap_err();
        assert!(matches!(err, InvalidAccessKey::EmptyKeyId));
    }

    #[test]
    fn empty_secret() {
        let err = "CSAKid.".parse::<AccessKey>().unwrap_err();
        assert!(matches!(err, InvalidAccessKey::EmptySecret));
    }

    #[test]
    fn empty_string() {
        let err = "".parse::<AccessKey>().unwrap_err();
        assert!(matches!(err, InvalidAccessKey::MissingPrefix));
    }

    #[test]
    fn debug_does_not_leak() {
        let key: AccessKey = "CSAKid.secret".parse().unwrap();
        let debug = format!("{key:?}");
        assert!(!debug.contains("secret"));
        assert_eq!(debug, "AccessKey(***)");
    }
}

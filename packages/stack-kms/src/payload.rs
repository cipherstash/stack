use recipher::key::Iv;
use std::borrow::Cow;
use zerokms_protocol::{Context, DecryptionPolicy, KeyId, RetrieveKeySpec, UnverifiedContext};

/// An input on a data-key request that only ZeroKMS can honour.
///
/// The vendor-neutral part of a request is its descriptor, its iv and tag,
/// and its keyset id. A key vendor backend works from these alone. The
/// inputs named here have no meaning there, so a key vendor backend refuses
/// a request that carries one ([`Error::ZeroKmsOnly`](crate::Error::ZeroKmsOnly))
/// and never ignores it. Find them with [`ZeroKmsExtensions`], or refuse them
/// in one call with [`refuse_zerokms_extensions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ZeroKmsFeature {
    /// A non-empty key [`Context`]: tags and identity claims bound into the
    /// data key.
    Context,
    /// A [`DecryptionPolicy`] that ZeroKMS checks on each retrieve.
    DecryptionPolicy,
    /// A non-empty [`UnverifiedContext`] sent with the request.
    UnverifiedContext,
}

impl ZeroKmsFeature {
    /// The feature as error payloads spell it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::DecryptionPolicy => "decryption_policy",
            Self::UnverifiedContext => "unverified_context",
        }
    }
}

impl std::fmt::Display for ZeroKmsFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A data-key payload that can carry ZeroKMS-only inputs.
///
/// Implemented by [`GenerateKeyPayload`] and [`RetrieveKeyPayload`]. A key
/// vendor backend calls [`refuse_zerokms_extensions`] (or this trait
/// directly) before it sends anything.
pub trait ZeroKmsExtensions {
    /// The first ZeroKMS-only input this payload carries, if any. An empty
    /// context is not an input: it binds nothing.
    fn zerokms_feature(&self) -> Option<ZeroKmsFeature>;
}

/// Refuse a request that carries a ZeroKMS-only input, for the key vendor
/// backend `vendor`.
///
/// Returns [`Error::ZeroKmsOnly`](crate::Error::ZeroKmsOnly) for the first
/// such input: a payload's context or decryption policy, else a non-empty
/// `unverified_context`. A key vendor backend calls this first in each
/// [`DataKeySource`](crate::DataKeySource) method, so that a lock context
/// or a policy is refused, not silently dropped.
pub fn refuse_zerokms_extensions<P: ZeroKmsExtensions>(
    vendor: crate::KeyVendor,
    payloads: &[P],
    unverified_context: Option<&UnverifiedContext>,
) -> Result<(), crate::Error> {
    let feature = payloads
        .iter()
        .find_map(ZeroKmsExtensions::zerokms_feature)
        .or_else(|| {
            unverified_context
                .filter(|context| !context.0.is_empty())
                .map(|_| ZeroKmsFeature::UnverifiedContext)
        });
    match feature {
        Some(feature) => Err(crate::Error::ZeroKmsOnly { vendor, feature }),
        None => Ok(()),
    }
}

/// The requirements for generating a data key.
///
/// [`descriptor`](Self::descriptor) is vendor-neutral. The context and the
/// decryption policy are ZeroKMS-only extensions ([`ZeroKmsFeature`]).
#[derive(Clone)]
pub struct GenerateKeyPayload<'a> {
    pub descriptor: &'a str,
    pub(crate) context: Cow<'a, [Context]>,
    pub decryption_policy: Option<DecryptionPolicy>,
}

impl<'a> GenerateKeyPayload<'a> {
    /// Create a new [`GenerateKeyPayload`] with the given descriptor and context.
    pub fn new(descriptor: &'a str, context: Cow<'a, [Context]>) -> Self {
        Self {
            descriptor,
            context,
            decryption_policy: None,
        }
    }

    pub fn with_decryption_policy(mut self, policy: DecryptionPolicy) -> Self {
        self.decryption_policy = Some(policy);
        self
    }

    /// The descriptor the data key is bound to.
    pub fn descriptor(&self) -> &'a str {
        self.descriptor
    }
}

impl ZeroKmsExtensions for GenerateKeyPayload<'_> {
    fn zerokms_feature(&self) -> Option<ZeroKmsFeature> {
        feature_of(&self.context, self.decryption_policy.as_ref())
    }
}

/// The ZeroKMS-only input a context and a policy carry, context first.
fn feature_of(
    context: &[Context],
    decryption_policy: Option<&DecryptionPolicy>,
) -> Option<ZeroKmsFeature> {
    if !context.is_empty() {
        Some(ZeroKmsFeature::Context)
    } else if decryption_policy.is_some() {
        Some(ZeroKmsFeature::DecryptionPolicy)
    } else {
        None
    }
}

/// The requirements for retrieving a data key.
///
/// The iv, the descriptor and the tag are vendor-neutral (see
/// [`iv_bytes`](Self::iv_bytes)). The context and the decryption policy are
/// ZeroKMS-only extensions ([`ZeroKmsFeature`]).
pub struct RetrieveKeyPayload<'a> {
    pub iv: KeyId,
    pub descriptor: &'a str,
    pub tag: &'a [u8],
    pub context: Cow<'a, [Context]>,
    pub decryption_policy: Option<DecryptionPolicy>,
    /// The key mode the leaf names, when a key vendor backend sealed it
    /// (a v2 leaf). `None` for a ZeroKMS leaf. A key vendor backend
    /// refuses a payload whose mode is not its keyset's.
    pub key_mode: Option<crate::KeyMode>,
}

impl<'a> RetrieveKeyPayload<'a> {
    /// Create a new [`RetrieveKeyPayload`] with the given IV, descriptor, and tag.
    pub fn new(iv: Iv, descriptor: &'a str, tag: &'a [u8]) -> Self {
        Self {
            iv: KeyId::from(iv),
            descriptor,
            tag,
            context: Default::default(),
            decryption_policy: None,
            key_mode: None,
        }
    }

    /// Name the key mode the leaf was sealed under (a v2 leaf).
    pub fn with_key_mode(mut self, mode: crate::KeyMode) -> Self {
        self.key_mode = Some(mode);
        self
    }

    pub fn with_context(mut self, context: Cow<'a, [Context]>) -> Self {
        self.context = context;
        self
    }

    pub fn with_decryption_policy(mut self, policy: DecryptionPolicy) -> Self {
        self.decryption_policy = Some(policy);
        self
    }

    /// The iv the data key was generated with, as plain bytes.
    pub fn iv_bytes(&self) -> Iv {
        *self.iv.as_ref()
    }
}

impl ZeroKmsExtensions for RetrieveKeyPayload<'_> {
    fn zerokms_feature(&self) -> Option<ZeroKmsFeature> {
        feature_of(&self.context, self.decryption_policy.as_ref())
    }
}

impl<'a> From<RetrieveKeyPayload<'a>> for RetrieveKeySpec<'a> {
    fn from(
        RetrieveKeyPayload {
            iv,
            descriptor,
            tag,
            context,
            decryption_policy,
            ..
        }: RetrieveKeyPayload<'a>,
    ) -> Self {
        let mut spec = Self::new(iv, tag, descriptor).with_context(context);
        if let Some(policy) = decryption_policy {
            spec = spec.with_policy(policy);
        }
        spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerokms_protocol::PolicyCondition;

    fn policy() -> DecryptionPolicy {
        DecryptionPolicy {
            conditions: vec![PolicyCondition {
                claim: "sub".into(),
                value: Some("alice".into()),
            }],
        }
    }

    mod retrieve_key_spec_from_payload {
        use super::*;

        #[test]
        fn carries_iv_descriptor_tag_and_context_without_a_policy() {
            let iv: Iv = [7u8; 16];
            let ctx = vec![Context::Tag("tenant-1".into())];
            let payload = RetrieveKeyPayload::new(iv, "users/email", b"tag")
                .with_context(Cow::Borrowed(&ctx));

            let spec = RetrieveKeySpec::from(payload);

            assert_eq!(spec.iv, KeyId::from(iv));
            assert_eq!(spec.descriptor, "users/email");
            assert_eq!(spec.tag.as_ref(), b"tag");
            assert_eq!(spec.context.len(), 1);
            assert!(spec.decryption_policy.is_none());
        }

        #[test]
        fn forwards_the_policy_when_present() {
            let payload =
                RetrieveKeyPayload::new([0u8; 16], "d", b"tag").with_decryption_policy(policy());

            let spec = RetrieveKeySpec::from(payload);

            assert_eq!(spec.decryption_policy, Some(policy()));
        }
    }

    mod zerokms_extensions {
        use super::*;
        use crate::{Error, KeyVendor};
        use std::collections::HashMap;

        fn tag() -> Vec<Context> {
            vec![Context::Tag("tenant-1".into())]
        }

        #[test]
        fn a_plain_payload_carries_no_zerokms_feature() {
            let generate = GenerateKeyPayload::new("d", Cow::Owned(vec![]));
            let retrieve = RetrieveKeyPayload::new([1u8; 16], "d", b"tag");
            assert_eq!(generate.zerokms_feature(), None);
            assert_eq!(retrieve.zerokms_feature(), None);
            assert_eq!(generate.descriptor(), "d");
            assert_eq!(retrieve.iv_bytes(), [1u8; 16]);
        }

        #[test]
        fn a_context_or_a_policy_is_a_zerokms_feature() {
            let ctx = tag();
            assert_eq!(
                GenerateKeyPayload::new("d", Cow::Borrowed(&ctx)).zerokms_feature(),
                Some(ZeroKmsFeature::Context)
            );
            assert_eq!(
                GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(policy())
                    .zerokms_feature(),
                Some(ZeroKmsFeature::DecryptionPolicy)
            );
            assert_eq!(
                RetrieveKeyPayload::new([0u8; 16], "d", b"t")
                    .with_context(Cow::Borrowed(&ctx))
                    .zerokms_feature(),
                Some(ZeroKmsFeature::Context)
            );
            assert_eq!(
                RetrieveKeyPayload::new([0u8; 16], "d", b"t")
                    .with_decryption_policy(policy())
                    .zerokms_feature(),
                Some(ZeroKmsFeature::DecryptionPolicy)
            );
        }

        fn refused(result: Result<(), Error>) -> ZeroKmsFeature {
            match result {
                Err(Error::ZeroKmsOnly { vendor, feature }) => {
                    assert_eq!(vendor, KeyVendor::Static);
                    feature
                }
                other => panic!("expected a ZeroKmsOnly refusal, got {other:?}"),
            }
        }

        #[test]
        fn a_vendor_refuses_every_zerokms_feature() {
            let ctx = tag();
            let plain = [GenerateKeyPayload::new("d", Cow::Owned(vec![]))];
            assert!(refuse_zerokms_extensions(KeyVendor::Static, &plain, None).is_ok());

            let with_context = [
                GenerateKeyPayload::new("d", Cow::Owned(vec![])),
                GenerateKeyPayload::new("d", Cow::Borrowed(&ctx)),
            ];
            assert_eq!(
                refused(refuse_zerokms_extensions(
                    KeyVendor::Static,
                    &with_context,
                    None
                )),
                ZeroKmsFeature::Context
            );

            let with_policy =
                [RetrieveKeyPayload::new([0u8; 16], "d", b"t").with_decryption_policy(policy())];
            assert_eq!(
                refused(refuse_zerokms_extensions(
                    KeyVendor::Static,
                    &with_policy,
                    None
                )),
                ZeroKmsFeature::DecryptionPolicy
            );

            let mut claims = HashMap::new();
            let _ = claims.insert("sub".to_string(), None);
            let unverified = UnverifiedContext(claims);
            assert_eq!(
                refused(refuse_zerokms_extensions(
                    KeyVendor::Static,
                    &plain,
                    Some(&unverified)
                )),
                ZeroKmsFeature::UnverifiedContext
            );
        }

        /// An empty unverified context carries nothing, so it is no input.
        #[test]
        fn an_empty_unverified_context_is_not_refused() {
            let plain = [GenerateKeyPayload::new("d", Cow::Owned(vec![]))];
            let empty = UnverifiedContext(HashMap::new());
            assert!(refuse_zerokms_extensions(KeyVendor::Static, &plain, Some(&empty)).is_ok());
        }

        #[test]
        fn every_feature_keeps_its_spelling() {
            for (feature, text) in [
                (ZeroKmsFeature::Context, "context"),
                (ZeroKmsFeature::DecryptionPolicy, "decryption_policy"),
                (ZeroKmsFeature::UnverifiedContext, "unverified_context"),
            ] {
                assert_eq!(feature.as_str(), text);
                assert_eq!(feature.to_string(), text);
            }
        }
    }

    #[test]
    fn generate_key_payload_with_decryption_policy_sets_the_policy() {
        let payload = GenerateKeyPayload::new("d", Cow::Owned(vec![]));
        assert!(payload.decryption_policy.is_none());

        let payload = payload.with_decryption_policy(policy());
        assert_eq!(payload.decryption_policy, Some(policy()));
    }
}

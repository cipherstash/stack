use recipher::key::Iv;
use std::borrow::Cow;
use zerokms_protocol::{Context, DecryptionPolicy, KeyId, RetrieveKeySpec};

/// The requirements for generating a data key from ZeroKMS.
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
}

/// The requirements for retrieving a data key from ZeroKMS.
pub struct RetrieveKeyPayload<'a> {
    pub iv: KeyId,
    pub descriptor: &'a str,
    pub tag: &'a [u8],
    pub context: Cow<'a, [Context]>,
    pub decryption_policy: Option<DecryptionPolicy>,
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
        }
    }

    pub fn with_context(mut self, context: Cow<'a, [Context]>) -> Self {
        self.context = context;
        self
    }

    pub fn with_decryption_policy(mut self, policy: DecryptionPolicy) -> Self {
        self.decryption_policy = Some(policy);
        self
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

    #[test]
    fn generate_key_payload_with_decryption_policy_sets_the_policy() {
        let payload = GenerateKeyPayload::new("d", Cow::Owned(vec![]));
        assert!(payload.decryption_policy.is_none());

        let payload = payload.with_decryption_policy(policy());
        assert_eq!(payload.decryption_policy, Some(policy()));
    }
}

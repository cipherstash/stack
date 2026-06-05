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

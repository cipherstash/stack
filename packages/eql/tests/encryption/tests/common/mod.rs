use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use stack_encrypt::StackCipher;
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;

#[derive(Default)]
pub struct Calls {
    pub generate: Vec<Vec<String>>,
    pub retrieve: Vec<Vec<String>>,
}

pub struct Observed {
    inner: FakeDataKeySource,
    calls: Arc<Mutex<Calls>>,
}
impl DataKeySource for Observed {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset: Option<Uuid>,
        context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.calls
            .lock()
            .unwrap()
            .generate
            .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
        self.inner.generate_keys(payloads, keyset, context).await
    }
    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset: Option<Uuid>,
        context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.calls
            .lock()
            .unwrap()
            .retrieve
            .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
        self.inner.retrieve_keys(payloads, keyset, context).await
    }
}
impl IndexKeySource for Observed {
    async fn load_index_key(
        &self,
        keyset: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset).await
    }
}
pub async fn cipher() -> (StackCipher<Observed>, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let cipher = StackCipher::builder()
        .kms(Observed {
            inner: FakeDataKeySource::new(),
            calls: calls.clone(),
        })
        .init()
        .await
        .unwrap();
    (cipher, calls)
}

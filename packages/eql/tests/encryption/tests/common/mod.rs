use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use stack_encrypt::StackCipher;
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;

/// What a [`RecordingKeySource`] has been asked for, in order.
#[derive(Default)]
pub struct Calls {
    /// The descriptor of each data key generated, one list per request.
    pub generate: Vec<Vec<String>>,
    /// The descriptor of each data key retrieved, one list per request.
    pub retrieve: Vec<Vec<String>>,
    /// Index key loads, one per keyset a call resolves after the cipher is
    /// built.
    pub loads: usize,
}

/// The fake key source every test in this crate encrypts with. It hands out
/// [`FakeDataKeySource`]'s keys, and records each request in [`Calls`]: the
/// descriptor of every data key generated or retrieved, and the number of
/// index key loads. So a test can check which context a key was asked for
/// under, or that a refused call asked for no key at all.
pub struct RecordingKeySource {
    inner: FakeDataKeySource,
    calls: Arc<Mutex<Calls>>,
}
impl stack_kms::KeySourceKind for RecordingKeySource {
    type Kind = stack_kms::OwnIdentity;
}

impl DataKeySource for RecordingKeySource {
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
impl IndexKeySource for RecordingKeySource {
    async fn load_index_key(
        &self,
        keyset: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.calls.lock().unwrap().loads += 1;
        self.inner.load_index_key(keyset).await
    }
}
/// A cipher over a [`RecordingKeySource`], and the calls it records. The
/// index key loaded while the cipher is built is not counted.
pub async fn cipher() -> (StackCipher<RecordingKeySource>, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let cipher = StackCipher::builder()
        .kms(RecordingKeySource {
            inner: FakeDataKeySource::new(),
            calls: calls.clone(),
        })
        .init()
        .await
        .unwrap();
    calls.lock().unwrap().loads = 0;
    (cipher, calls)
}

/// The index a query on the named type is asked through when the test does
/// not care which: the first the type carries. Equality for a name with no
/// row or no index, which a test of a refusal names; the refusal comes
/// before the index is read.
// Not every suite that includes this module queries by name.
#[allow(dead_code)]
pub fn index_of(name: &str) -> stack_encrypt::target::IndexSpec {
    use stack_encrypt::target::IndexSpec;
    eql_bindings::encryption::targets::target(name)
        .and_then(|target| target.indexes.first())
        .and_then(|key| IndexSpec::parse(key))
        .unwrap_or(IndexSpec::Equality)
}

/// The date `days` days after 1970-01-01, as the plaintext the `date`
/// family takes.
#[allow(dead_code)]
pub fn date_of_days(days: i32) -> eql_bindings::v4::plaintext::Date {
    let day = jiff::civil::date(1970, 1, 1)
        .checked_add(jiff::Span::new().days(days))
        .expect("a day in jiff's range");
    eql_bindings::v4::plaintext::Date::new(day)
}

/// The instant `seconds` after the Unix epoch plus `nanoseconds`, as the
/// plaintext the `timestamp` family takes.
#[allow(dead_code)]
pub fn timestamp_of(seconds: i64, nanoseconds: i32) -> eql_bindings::v4::plaintext::Timestamp {
    let instant = jiff::Timestamp::new(seconds, nanoseconds).expect("an instant in jiff's range");
    eql_bindings::v4::plaintext::Timestamp::new(instant).expect("an instant in range")
}

/// The number `mantissa × 10^-scale`, as the plaintext the `numeric`
/// family takes.
#[allow(dead_code)]
pub fn decimal_of(mantissa: i128, scale: u32) -> eql_bindings::v4::plaintext::Decimal {
    eql_bindings::v4::plaintext::Decimal::new(rust_decimal::Decimal::from_i128_with_scale(
        mantissa, scale,
    ))
}

/// The order of two block ORE `ob` terms of the type `name`, by ore-rs's
/// comparator, which EQL v4's comparator agrees with
/// (tests/v4_ore_block.rs).
#[allow(dead_code)]
pub fn ob_order(name: &str, a: &serde_json::Value, b: &serde_json::Value) -> std::cmp::Ordering {
    fn compare<T: stack_encrypt::Orderable>(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        let a = stack_encrypt::sem::OreBlockTerm::<T>::try_from(a).unwrap();
        let b = stack_encrypt::sem::OreBlockTerm::<T>::try_from(b).unwrap();
        a.compare(&b).expect("terms of one index compare")
    }
    let unhex = |term: &serde_json::Value| -> Vec<u8> {
        let hex = term.as_str().expect("an `ob` term is one hex string");
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    };
    let (a, b) = (unhex(a), unhex(b));
    let family = [
        "Integer",
        "Smallint",
        "Bigint",
        "Date",
        "Timestamp",
        "Numeric",
        "Text",
        "Real",
        "Double",
    ]
    .into_iter()
    .find(|family| name.starts_with(family))
    .unwrap_or_else(|| panic!("{name}: no family"));
    match family {
        "Integer" => compare::<i32>(&a, &b),
        "Smallint" => compare::<i16>(&a, &b),
        "Bigint" => compare::<i64>(&a, &b),
        "Date" => compare::<eql_bindings::v4::plaintext::Date>(&a, &b),
        "Timestamp" => compare::<eql_bindings::v4::plaintext::Timestamp>(&a, &b),
        "Numeric" => compare::<eql_bindings::v4::plaintext::Decimal>(&a, &b),
        "Text" => compare::<String>(&a, &b),
        "Real" => compare::<f32>(&a, &b),
        _ => compare::<f64>(&a, &b),
    }
}

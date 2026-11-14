//! `decrypt`: stored rows into the engine's record tree, the engine's record
//! decryption under a model's plan, and the walk of the opened frame into
//! one row of values per stored row.
//!
//! The extension reads each row's columns with the GIL held and hands them
//! to a [`Row`]: an EQL column as its JSON text, a passthrough column as a
//! value already checked by exact type. Everything a row can answer is
//! checked there, before any key request (the spec in #1341, "Errors"): the
//! JSON parses, and its `i` names this table and column. Then the engine
//! opens the whole batch under one pending, and [`decrypt`] reads the opened
//! frame back as a [`Scalar`] per field.

use std::future::Future;

use stack_encrypt::dynamic::frame;
use stack_encrypt::dynamic::plaintext::{FixedType, Logical, MapSink, Physical, SeqSink, Sink};
use stack_encrypt::dynamic::record::{self, EQL_KEY};
use stack_encrypt::dynamic::{Output, Scope, ValueFrame};
use stack_encrypt::kms::{DataKeySource, IndexKeySource};
use stack_encrypt::{
    CipherText, Controlled as _, Encrypt, PassthroughFrame, StackCipher, StackCipherText,
};

use crate::client;
use crate::encrypt::{engine_fault, Field, ModelPlan};
use crate::plan;
use crate::refusal::Refusal;
use crate::targets;
use crate::values::{self, Misfit, Never, ReadError, Scalar, Typed, Value};

/// The stored rows of one `decrypt` call, as the engine's record tree.
#[derive(Default)]
pub struct Rows {
    rows: Vec<StackCipherText>,
}

impl Rows {
    /// No rows yet, with room for `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            rows: Vec::with_capacity(capacity),
        }
    }

    /// How many rows were added.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no row was added.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Add one row, its columns added in any order.
    pub fn push(&mut self, row: Row) {
        self.rows.push(CipherText::Map(row.fields));
    }
}

/// One stored row, built a column at a time.
#[derive(Default)]
pub struct Row {
    fields: Vec<(String, StackCipherText)>,
}

impl Row {
    /// An empty row.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `field`'s EQL column, given as its JSON text.
    ///
    /// # Errors
    ///
    /// `decrypt_malformed` when the text is not a JSON object with an `i`
    /// naming a table and a column; `decrypt_foreign_row` when that `i`
    /// names another table or column than `field` of `plan`. Both name the
    /// field.
    pub fn eql(&mut self, plan: &ModelPlan, field: &Field, json: &[u8]) -> Result<(), Refusal> {
        let (table, column) = identifier(json).ok_or_else(|| {
            refusal(
                "decrypt_malformed",
                field,
                "the column value is not an EQL value: JSON text of an object with an \
                 \"i\" naming its table and column."
                    .to_owned(),
            )
        })?;
        if table != plan.table() || column != field.name {
            return Err(refusal(
                "decrypt_foreign_row",
                field,
                format!(
                    "the column value was stored under another table or column, not {:?}.{:?}. \
                     Check the query selects this model's table and column.",
                    plan.table(),
                    field.name
                ),
            ));
        }
        self.add(field, EQL_KEY, eql_frame(json));
        Ok(())
    }

    /// Add `field`'s passthrough column, a value the extension has already
    /// checked by exact type against the field's annotation.
    ///
    /// # Errors
    ///
    /// The [`Misfit`] when the value is outside what the engine carries,
    /// such as an integer wider than 128 bits.
    pub fn passthrough(&mut self, field: &Field, value: Value<'_>) -> Result<(), Misfit> {
        values::scalar(None, value)?;
        // A value that fits always writes.
        let frame = ValueFrame::of(Typed(None, value)).map_err(|_| Misfit::OutOfRange)?;
        self.add(field, Output::Passthrough.key(), frame.risky_ref().to_vec());
        Ok(())
    }

    fn add(&mut self, field: &Field, key: &str, frame: Vec<u8>) {
        let node = CipherText::Passthrough(PassthroughFrame(frame));
        self.fields.push((
            field.name.clone(),
            CipherText::Map(vec![(key.to_owned(), node)]),
        ));
    }
}

/// An EQL value's JSON text as the frame of one bytes scalar, the way the
/// engine stores it: written straight into the frame's buffer, so the text
/// is copied once. Bytes are ciphertext here, not plaintext.
fn eql_frame(json: &[u8]) -> Vec<u8> {
    struct Bytes<'a>(&'a [u8]);
    impl serde::Serialize for Bytes<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }
    // One bytes scalar always encodes. The frame comes back in vitaminc's
    // wiped Buffer, made for plaintext; this one holds ciphertext, and a
    // passthrough frame takes plain bytes.
    frame::serde::to_vec(&Bytes(json))
        .expect("a bytes scalar encodes as a frame")
        .risky_unwrap()
}

/// The `i.t` and `i.c` of an EQL value's JSON text, or `None` when it is not
/// JSON text of an object with both.
fn identifier(json: &[u8]) -> Option<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Stored {
        i: Identifier,
    }
    #[derive(serde::Deserialize)]
    struct Identifier {
        t: String,
        c: String,
    }
    let stored: Stored = serde_json::from_slice(json).ok()?;
    Some((stored.i.t, stored.i.c))
}

fn refusal(code: &str, field: &Field, message: String) -> Refusal {
    Refusal {
        code: code.to_owned(),
        message: format!("field {:?}: {message}", field.name),
        field: Some(field.name.clone()),
        reason: None,
    }
}

/// Decrypt `rows` under `plan` on the shared client. Returns one row of
/// values per stored row, in [`ModelPlan::fields`] order.
///
/// Builds the shared client on the first call in the process. The caller
/// has released the GIL.
///
/// # Errors
///
/// The client's refusal, or the engine's for the decryption:
/// `decrypt_kind_mismatch` for a value stored as another kind than the
/// field's.
pub fn decrypt(plan: &ModelPlan, rows: Rows) -> Result<Vec<Vec<Scalar>>, Refusal> {
    client::run!(|cipher| decrypt_with(cipher, plan, rows))
}

/// [`decrypt`] on `cipher`. Each value opens under the keyset that sealed
/// it, with the keys requested per keyset, as the Go SDK's `Client.Open`
/// does: rows another SDK wrote under another keyset of the same client
/// decrypt here too.
///
/// # Errors
///
/// As [`decrypt`].
pub fn decrypt_with<'a, K>(
    cipher: &'a StackCipher<K>,
    plan: &'a ModelPlan,
    rows: Rows,
) -> impl Future<Output = Result<Vec<Vec<Scalar>>, Refusal>> + 'a
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let count = rows.len();
    async move {
        let scope = Scope::Client(cipher);
        let tree = CipherText::Sequence(rows.rows);
        let pending = record::decrypt_with(scope, tree, plan.plan(), None, &targets::resolver())
            .map_err(|error| opening(plan, &plan::refusal(&error)))?;
        let frame = pending
            .await
            .map_err(|error| opening(plan, &Refusal::of(&error)))?;
        read_rows(plan, &frame, count)
    }
}

/// An engine refusal of the decryption, with the SDK's code where the spec
/// gives one.
///
/// `stack_encrypt_target_stored` comes before any key request: the JSON has
/// an `i` but is not the field's EQL type. `stack_encrypt_opened_type` comes
/// after: the value opened, but was sealed as another type. The engine does
/// not say which field that was. So the field is named only when the plan
/// has one sealed field. #1508 tracks the engine change that names it.
fn opening(plan: &ModelPlan, refused: &Refusal) -> Refusal {
    let code = match refused.code.as_str() {
        "stack_encrypt_target_stored" => "decrypt_malformed",
        "stack_encrypt_opened_type" => "decrypt_kind_mismatch",
        _ => return refused.clone(),
    };
    let mut sealed = plan.fields().iter().filter(|field| field.eql.is_some());
    let field = match (refused.field.clone(), sealed.next(), sealed.next()) {
        (Some(field), _, _) => Some(field),
        (None, Some(only), None) => Some(only.name.clone()),
        _ => None,
    };
    Refusal {
        code: code.to_owned(),
        message: match &field {
            Some(name) if refused.field.is_none() => format!("field {name:?}: {}", refused.message),
            _ => refused.message.clone(),
        },
        field,
        reason: refused.reason.clone(),
    }
}

fn read_rows(
    plan: &ModelPlan,
    frame: &ValueFrame,
    count: usize,
) -> Result<Vec<Vec<Scalar>>, Refusal> {
    let mut rows = Vec::with_capacity(count);
    frame
        .visit(Opened {
            fields: plan.fields(),
            rows: &mut rows,
        })
        .map_err(|ReadError(what)| engine_fault(what))?;
    if rows.len() != count {
        return Err(engine_fault(
            "the output has another number of rows than the input",
        ));
    }
    Ok(rows)
}

fn not_expected<T>(what: &'static str) -> Result<T, ReadError> {
    Err(ReadError(what))
}

/// The opened frame: a sequence of maps, one per stored row.
struct Opened<'a> {
    fields: &'a [Field],
    rows: &'a mut Vec<Vec<Scalar>>,
}

impl<'a> Sink for Opened<'a> {
    type Ok = ();
    type Error = ReadError;
    type Seq = Self;
    type Map = Never<(), OpenedValue<'static>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), ReadError> {
        not_expected("a scalar in place of the rows")
    }

    fn typed_null(self, _: FixedType) -> Result<(), ReadError> {
        not_expected("a null in place of the rows")
    }

    fn seq(self, _: Option<usize>) -> Result<Self, ReadError> {
        Ok(self)
    }

    fn map(self, _: Option<usize>) -> Result<Never<(), OpenedValue<'static>>, ReadError> {
        not_expected("one record in place of the rows")
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), ReadError> {
        not_expected("a passthrough in place of the rows")
    }
}

impl SeqSink for Opened<'_> {
    type Ok = ();
    type Error = ReadError;
    type Element<'s>
        = OpenedRow<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<OpenedRow<'_>, ReadError> {
        Ok(OpenedRow {
            fields: self.fields,
            rows: self.rows,
        })
    }

    fn end(self) -> Result<(), ReadError> {
        Ok(())
    }
}

/// One opened row: a map of the plan's fields.
struct OpenedRow<'a> {
    fields: &'a [Field],
    rows: &'a mut Vec<Vec<Scalar>>,
}

impl<'a> Sink for OpenedRow<'a> {
    type Ok = ();
    type Error = ReadError;
    type Seq = Never<(), OpenedValue<'static>>;
    type Map = OpenedFields<'a>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), ReadError> {
        not_expected("a scalar in place of a row")
    }

    fn typed_null(self, _: FixedType) -> Result<(), ReadError> {
        not_expected("a null in place of a row")
    }

    fn seq(self, _: Option<usize>) -> Result<Never<(), OpenedValue<'static>>, ReadError> {
        not_expected("a sequence in place of a row")
    }

    fn map(self, _: Option<usize>) -> Result<OpenedFields<'a>, ReadError> {
        Ok(OpenedFields {
            values: vec![Scalar::Null; self.fields.len()],
            seen: vec![false; self.fields.len()],
            fields: self.fields,
            rows: self.rows,
        })
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), ReadError> {
        not_expected("a passthrough in place of a row")
    }
}

/// One row as it opens. Each value is written into its slot, and `end`
/// moves the whole buffer into the rows: no value is moved out of a buffer
/// that is then freed with its bytes still in it.
struct OpenedFields<'a> {
    fields: &'a [Field],
    values: Vec<Scalar>,
    seen: Vec<bool>,
    rows: &'a mut Vec<Vec<Scalar>>,
}

impl MapSink for OpenedFields<'_> {
    type Ok = ();
    type Error = ReadError;
    type Entry<'s>
        = OpenedValue<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<OpenedValue<'_>, ReadError> {
        let at = self
            .fields
            .iter()
            .position(|field| field.name == key)
            .ok_or(ReadError("a field the plan does not have"))?;
        Ok(OpenedValue {
            slot: &mut self.values[at],
            seen: &mut self.seen[at],
        })
    }

    fn end(self) -> Result<(), ReadError> {
        if !self.seen.iter().all(|&seen| seen) {
            return Err(ReadError("a row without one of the plan's fields"));
        }
        self.rows.push(self.values);
        Ok(())
    }
}

/// One opened field: one scalar.
struct OpenedValue<'a> {
    slot: &'a mut Scalar,
    seen: &'a mut bool,
}

impl OpenedValue<'_> {
    fn put(self, scalar: Scalar) -> Result<(), ReadError> {
        if std::mem::replace(self.seen, true) {
            return not_expected("a field twice in one row");
        }
        *self.slot = scalar;
        Ok(())
    }
}

impl Sink for OpenedValue<'_> {
    type Ok = ();
    type Error = ReadError;
    type Seq = Never<(), OpenedValue<'static>>;
    type Map = Never<(), OpenedValue<'static>>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), ReadError> {
        self.put(values::scalar_of(ty, value).map_err(ReadError)?)
    }

    fn typed_null(self, _: FixedType) -> Result<(), ReadError> {
        self.put(Scalar::Null)
    }

    fn seq(self, _: Option<usize>) -> Result<Never<(), OpenedValue<'static>>, ReadError> {
        not_expected("a sequence in place of a value")
    }

    fn map(self, _: Option<usize>) -> Result<Never<(), OpenedValue<'static>>, ReadError> {
        not_expected("a map in place of a value")
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), ReadError> {
        not_expected("a nested passthrough")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::encrypt::{encrypt_with, Column};
    use crate::values::Kind;
    use stack_kms::FakeDataKeySource;

    pub(crate) fn run<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    pub(crate) fn cipher() -> StackCipher<FakeDataKeySource> {
        run(StackCipher::builder().kms(FakeDataKeySource::new()).init()).unwrap()
    }

    fn sealed(name: &str, eql: &str, kind: Kind) -> Field {
        Field {
            name: name.to_owned(),
            eql: Some((eql.to_owned(), kind)),
            nullable: false,
        }
    }

    fn passthrough(name: &str) -> Field {
        Field {
            name: name.to_owned(),
            eql: None,
            nullable: false,
        }
    }

    pub(crate) fn users() -> ModelPlan {
        ModelPlan::new(
            "users",
            vec![sealed("email", "TextEq", Kind::String), passthrough("age")],
        )
        .unwrap()
    }

    /// Rows of `(field, kind, value)` as the input frame `encrypt` takes.
    struct Source<'a>(Vec<Vec<(&'a str, Option<Kind>, Value<'a>)>>);

    impl Encrypt for Source<'_> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut rows = sink.seq(Some(self.0.len()))?;
            for row in self.0 {
                let mut map = rows.element()?.map(Some(row.len()))?;
                for (name, kind, value) in row {
                    let entry = map.entry(name)?;
                    values::write(entry, kind, value)?;
                }
                map.end()?;
            }
            rows.end()
        }
    }

    /// Encrypt one `users` row per email, with `age` 30 + its index.
    pub(crate) fn stored(
        cipher: &StackCipher<FakeDataKeySource>,
        plan: &ModelPlan,
        emails: &[&str],
    ) -> Vec<Vec<Column>> {
        let rows = emails
            .iter()
            .enumerate()
            .map(|(at, email)| {
                vec![
                    ("email", Some(Kind::String), Value::Text(email)),
                    ("age", None, Value::Int(30 + at as i128)),
                ]
            })
            .collect();
        let source = ValueFrame::of(Source(rows)).unwrap();
        run(encrypt_with(
            &cipher.default_keyset(),
            plan,
            source,
            emails.len(),
        ))
        .unwrap()
    }

    /// The stored columns back as one [`Row`] each, as the extension adds them.
    fn rows_of(plan: &ModelPlan, stored: &[Vec<Column>]) -> Rows {
        let mut rows = Rows::with_capacity(stored.len());
        for columns in stored {
            let mut row = Row::new();
            for (field, column) in plan.fields().iter().zip(columns) {
                match column {
                    Column::Eql(json) => row.eql(plan, field, json.as_bytes()).unwrap(),
                    Column::Passthrough(Scalar::Int(i)) => {
                        row.passthrough(field, Value::Int(*i)).unwrap()
                    }
                    Column::Passthrough(other) => panic!("not an age: {other:?}"),
                    Column::Null => panic!("no field here is nullable"),
                }
            }
            rows.push(row);
        }
        rows
    }

    fn eql(columns: &[Column]) -> &str {
        match &columns[0] {
            Column::Eql(json) => json,
            other => panic!("not EQL: {other:?}"),
        }
    }

    #[test]
    fn an_eql_frame_is_the_frame_of_one_bytes_scalar() {
        let json = br#"{"i":{"t":"users","c":"email"}}"#;
        let scalar = ValueFrame::of(Typed(None, Value::Bytes(json))).unwrap();
        assert_eq!(eql_frame(json), scalar.risky_ref());
    }

    #[test]
    fn a_batch_round_trips_through_encrypt_and_decrypt() {
        let cipher = cipher();
        let plan = users();
        let stored = stored(&cipher, &plan, &["a@example.com", "b@example.com"]);

        let opened = run(decrypt_with(&cipher, &plan, rows_of(&plan, &stored))).unwrap();

        assert_eq!(
            opened,
            vec![
                vec![Scalar::Text("a@example.com".to_owned()), Scalar::Int(30)],
                vec![Scalar::Text("b@example.com".to_owned()), Scalar::Int(31)],
            ]
        );
    }

    #[test]
    fn a_row_sealed_under_another_keyset_of_the_client_decrypts() {
        let cipher = cipher();
        let plan = users();
        let named = stack_kms::IdentifiedBy::Name("acme".to_owned().into());
        let acme = run(cipher.keyset(named)).unwrap();
        let source = ValueFrame::of(Source(vec![vec![
            ("email", Some(Kind::String), Value::Text("a@example.com")),
            ("age", None, Value::Int(3)),
        ]]))
        .unwrap();
        let stored = run(encrypt_with(&acme, &plan, source, 1)).unwrap();

        let opened = run(decrypt_with(&cipher, &plan, rows_of(&plan, &stored))).unwrap();

        assert_eq!(
            opened,
            vec![vec![
                Scalar::Text("a@example.com".to_owned()),
                Scalar::Int(3)
            ]]
        );
    }

    #[test]
    fn a_value_from_another_table_is_a_foreign_row() {
        let cipher = cipher();
        let stored = stored(&cipher, &users(), &["a@example.com"]);
        let accounts = ModelPlan::new(
            "accounts",
            vec![sealed("email", "TextEq", Kind::String), passthrough("age")],
        )
        .unwrap();

        let refused = Row::new()
            .eql(&accounts, &accounts.fields()[0], eql(&stored[0]).as_bytes())
            .unwrap_err();

        assert_eq!(refused.code, "decrypt_foreign_row");
        assert_eq!(refused.field.as_deref(), Some("email"));
    }

    #[test]
    fn a_value_from_another_column_is_a_foreign_row() {
        let cipher = cipher();
        let stored = stored(&cipher, &users(), &["a@example.com"]);
        let plan = ModelPlan::new("users", vec![sealed("login", "TextEq", Kind::String)]).unwrap();

        let refused = Row::new()
            .eql(&plan, &plan.fields()[0], eql(&stored[0]).as_bytes())
            .unwrap_err();

        assert_eq!(refused.code, "decrypt_foreign_row");
        assert_eq!(refused.field.as_deref(), Some("login"));
    }

    #[test]
    fn text_that_is_not_an_eql_value_is_malformed() {
        let cipher = cipher();
        let plan = users();
        let stored = stored(&cipher, &plan, &["a@example.com"]);
        let json = eql(&stored[0]);
        let truncated = &json.as_bytes()[..json.len() / 2];

        for bytes in [truncated, b"[]", b"{}", b"{\"i\": 1}", b"\xff"] {
            let refused = Row::new().eql(&plan, &plan.fields()[0], bytes).unwrap_err();
            assert_eq!(refused.code, "decrypt_malformed", "{bytes:?}");
            assert_eq!(refused.field.as_deref(), Some("email"));
        }
    }

    #[test]
    fn an_eql_value_with_only_an_identifier_is_refused_before_any_key_request() {
        let cipher = cipher();
        let plan = users();
        let mut row = Row::new();
        row.eql(
            &plan,
            &plan.fields()[0],
            br#"{"i": {"t": "users", "c": "email"}}"#,
        )
        .unwrap();
        row.passthrough(&plan.fields()[1], Value::Int(1)).unwrap();
        let mut rows = Rows::default();
        rows.push(row);

        let refused = run(decrypt_with(&cipher, &plan, rows)).unwrap_err();

        assert_eq!(refused.code, "decrypt_malformed", "{refused:?}");
        assert_eq!(refused.field.as_deref(), Some("email"));
    }

    #[test]
    fn an_eql_value_with_only_an_identifier_names_its_field_among_several() {
        let cipher = cipher();
        let stored = stored(&cipher, &users(), &["a@example.com"]);
        let plan = ModelPlan::new(
            "users",
            vec![
                sealed("email", "TextEq", Kind::String),
                sealed("login", "TextEq", Kind::String),
            ],
        )
        .unwrap();
        let mut row = Row::new();
        row.eql(&plan, &plan.fields()[0], eql(&stored[0]).as_bytes())
            .unwrap();
        row.eql(
            &plan,
            &plan.fields()[1],
            br#"{"i": {"t": "users", "c": "login"}}"#,
        )
        .unwrap();
        let mut rows = Rows::default();
        rows.push(row);

        let refused = run(decrypt_with(&cipher, &plan, rows)).unwrap_err();

        assert_eq!(refused.code, "decrypt_malformed", "{refused:?}");
        assert_eq!(refused.field.as_deref(), Some("login"), "{refused:?}");
    }

    #[test]
    fn a_value_stored_as_another_kind_is_a_kind_mismatch() {
        let cipher = cipher();
        let numbers =
            ModelPlan::new("users", vec![sealed("email", "IntegerEq", Kind::Int32)]).unwrap();
        let source = ValueFrame::of(Source(vec![vec![(
            "email",
            Some(Kind::Int32),
            Value::Int(7),
        )]]))
        .unwrap();
        let stored = run(encrypt_with(&cipher.default_keyset(), &numbers, source, 1)).unwrap();
        let text = ModelPlan::new("users", vec![sealed("email", "TextEq", Kind::String)]).unwrap();
        let mut row = Row::new();
        row.eql(&text, &text.fields()[0], eql(&stored[0]).as_bytes())
            .unwrap();
        let mut rows = Rows::default();
        rows.push(row);

        let refused = run(decrypt_with(&cipher, &text, rows)).unwrap_err();

        assert_eq!(refused.code, "decrypt_kind_mismatch", "{refused:?}");
        assert_eq!(refused.field.as_deref(), Some("email"));
    }

    /// `people` with a nullable sealed field and a nullable passthrough.
    fn people() -> ModelPlan {
        ModelPlan::new(
            "people",
            vec![
                Field {
                    name: "city".to_owned(),
                    eql: Some(("TextEq".to_owned(), Kind::String)),
                    nullable: true,
                },
                Field {
                    name: "email".to_owned(),
                    eql: Some(("TextEq".to_owned(), Kind::String)),
                    nullable: false,
                },
                Field {
                    name: "note".to_owned(),
                    eql: None,
                    nullable: true,
                },
            ],
        )
        .unwrap()
    }

    fn people_rows<'a>(rows: &[(Value<'a>, &'a str, Value<'a>)]) -> ValueFrame {
        ValueFrame::of(Source(
            rows.iter()
                .map(|(city, email, note)| {
                    vec![
                        ("city", Some(Kind::String), *city),
                        ("email", Some(Kind::String), Value::Text(email)),
                        ("note", None, *note),
                    ]
                })
                .collect(),
        ))
        .unwrap()
    }

    #[test]
    fn a_null_in_a_nullable_field_is_stored_as_sql_null_and_opens_as_null() {
        let cipher = cipher();
        let plan = people();
        let source = people_rows(&[
            (Value::Null, "a@example.com", Value::Null),
            (Value::Text("Leeds"), "b@example.com", Value::Text("hi")),
        ]);

        let stored = run(encrypt_with(&cipher.default_keyset(), &plan, source, 2)).unwrap();

        assert!(matches!(stored[0][0], Column::Null));
        assert!(matches!(
            stored[0][2],
            Column::Null | Column::Passthrough(Scalar::Null)
        ));
        assert!(matches!(stored[1][0], Column::Eql(_)));

        let mut rows = Rows::default();
        for columns in &stored {
            let mut row = Row::new();
            for (field, column) in plan.fields().iter().zip(columns) {
                match column {
                    Column::Eql(json) => row.eql(&plan, field, json.as_bytes()).unwrap(),
                    Column::Passthrough(Scalar::Text(text)) => {
                        row.passthrough(field, Value::Text(text)).unwrap()
                    }
                    // A passthrough is always in the row, as a null here.
                    Column::Passthrough(Scalar::Null) => {
                        row.passthrough(field, Value::Null).unwrap()
                    }
                    // A nullable EQL field's SQL NULL: no entry.
                    Column::Null if field.eql.is_some() => {}
                    Column::Null => row.passthrough(field, Value::Null).unwrap(),
                    Column::Passthrough(other) => panic!("not a note: {other:?}"),
                }
            }
            rows.push(row);
        }
        let opened = run(decrypt_with(&cipher, &plan, rows)).unwrap();

        assert_eq!(
            opened,
            vec![
                vec![
                    Scalar::Null,
                    Scalar::Text("a@example.com".to_owned()),
                    Scalar::Null
                ],
                vec![
                    Scalar::Text("Leeds".to_owned()),
                    Scalar::Text("b@example.com".to_owned()),
                    Scalar::Text("hi".to_owned()),
                ],
            ]
        );
    }

    #[test]
    fn a_null_in_a_field_that_is_not_nullable_is_refused() {
        let cipher = cipher();
        let source = ValueFrame::of(Source(vec![vec![
            ("city", Some(Kind::String), Value::Text("Leeds")),
            ("email", Some(Kind::String), Value::Null),
            ("note", None, Value::Text("hi")),
        ]]))
        .unwrap();

        let refused = run(encrypt_with(&cipher.default_keyset(), &people(), source, 1));

        assert!(refused.is_err(), "{refused:?}");
    }
}

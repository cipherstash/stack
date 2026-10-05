//! How a value is taken apart field by field ([`Fields`], [`Field`]), and the
//! map-like record a fields plan produces and reads ([`FieldValues`]).
use std::any::{type_name, Any, TypeId};
use std::fmt;
use std::sync::Arc;

use super::PlanError;
use crate::Error;

/// A value a fields plan can take apart: it names its top-level fields.
///
/// A fields plan is fail-closed in both directions: every field the value
/// names must be named by the plan, and every field the plan names must be
/// in the value. [`field_names`](Self::field_names) is what the plan checks
/// the value against when it runs; [`schema`](Self::schema), when a type
/// fixes its fields, lets [`build`](super::FieldsBuilder::build) make the
/// same check, and the type check, before there is a value at all.
///
/// Each field is read through [`Field<F>`], one implementation per field
/// type. That is what `#[derive(EncryptFrom)]` is expected to emit for a
/// record, and what a binding's dynamic value implements with `F` its one
/// runtime value type.
///
/// ```
/// use stack_encrypt::plan::{Field, FieldSchema, Fields};
///
/// struct User {
///     email: String,
///     age: u32,
/// }
///
/// impl Fields for User {
///     fn field_names(&self) -> Vec<&str> {
///         vec!["email", "age"]
///     }
///     fn schema() -> Option<Vec<FieldSchema>> {
///         Some(vec![FieldSchema::of::<String>("email"), FieldSchema::of::<u32>("age")])
///     }
/// }
/// impl Field<String> for User {
///     fn field(&self, name: &str) -> Option<&String> {
///         (name == "email").then_some(&self.email)
///     }
/// }
/// impl Field<u32> for User {
///     fn field(&self, name: &str) -> Option<&u32> {
///         (name == "age").then_some(&self.age)
///     }
/// }
/// ```
pub trait Fields {
    /// The names of this value's top-level fields.
    fn field_names(&self) -> Vec<&str>;

    /// The fields every value of this type has, with their types, when the
    /// type fixes them; `None` (the default) when only a value knows, as for
    /// a dynamic map. With a schema, a plan that names a field the type does
    /// not have, leaves one of its fields unnamed, or names one at the wrong
    /// type is refused by `build()` rather than when it first runs.
    fn schema() -> Option<Vec<FieldSchema>>
    where
        Self: Sized,
    {
        None
    }
}

/// Read one field of a [`Fields`] value as `F`.
///
/// Returns `None` when the value has no field of that name, or has one of
/// another type; a plan tells the two apart through
/// [`field_names`](Fields::field_names) and reports which.
pub trait Field<F>: Fields {
    /// The field named `name`, if the value has one of type `F`.
    fn field(&self, name: &str) -> Option<&F>;
}

/// One field of a type's [`schema`](Fields::schema): its name and type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSchema {
    name: &'static str,
    type_id: TypeId,
    type_name: &'static str,
}

impl FieldSchema {
    /// The field `name`, of type `F`.
    pub fn of<F: 'static>(name: &'static str) -> Self {
        Self {
            name,
            type_id: TypeId::of::<F>(),
            type_name: type_name::<F>(),
        }
    }

    /// The field's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The field's type, by id.
    pub fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// The field's type, by name, for messages.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }
}

/// One value in a [`FieldValues`]: the value, and its type's name so the
/// record can say what it holds without showing it.
pub(crate) struct Slot {
    value: Box<dyn Any + Send>,
    type_name: &'static str,
}

impl Slot {
    pub(crate) fn new<T: Any + Send>(value: T) -> Self {
        Self {
            value: Box::new(value),
            type_name: type_name::<T>(),
        }
    }

    /// The value as `T`, or the slot back unchanged.
    pub(crate) fn downcast<T: Any>(self) -> Result<T, Self> {
        let type_name = self.type_name;
        self.value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|value| Self { value, type_name })
    }

    pub(crate) fn type_name(&self) -> &'static str {
        self.type_name
    }
}

/// A record of named fields: what a fields plan produces when it encrypts
/// a value, what it reads when it decrypts one, and what decrypting
/// produces.
///
/// It is the plan's output shape, not a type the caller declares: a plan
/// is data, built at run time by a person, the derive or a binding, so its
/// output cannot be a Rust struct named in advance. Each field holds the
/// type its verb produces, and is read back by name and type with
/// [`take`](Self::take) or [`get`](Self::get):
///
/// | field verb | encrypted field | decrypted field |
/// |---|---|---|
/// | `encrypt` | [`StackCipherText`](crate::StackCipherText) | the field's type |
/// | `encrypt_index` | [`Encrypted<Terms>`](crate::Encrypted) | the field's type |
/// | `index` | the index set's terms (a term, or a tuple of them) | absent: terms are one-way |
/// | `passthrough` | the field's type, unchanged | the field's type |
///
/// A typed record is the derive's job: it converts this into a struct with
/// the same field names. A record read from storage is assembled with
/// [`insert`](Self::insert); an `encrypt_index` field may then hold its
/// `StackCipherText` alone, since decrypting needs only the ciphertext.
///
/// Its [`Debug`](fmt::Debug) shows each field's name and type, never a
/// value: a decrypted record holds plaintext.
#[derive(Default)]
pub struct FieldValues {
    slots: Vec<(Arc<str>, Slot)>,
}

impl FieldValues {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn from_slots(slots: Vec<(Arc<str>, Slot)>) -> Self {
        Self { slots }
    }

    /// Set the field `name` to `value`, replacing any value it had.
    pub fn insert<T: Any + Send>(&mut self, name: &str, value: T) -> &mut Self {
        let slot = Slot::new(value);
        match self.slots.iter_mut().find(|(have, _)| &**have == name) {
            Some((_, existing)) => *existing = slot,
            None => self.slots.push((Arc::from(name), slot)),
        }
        self
    }

    /// The field `name`, if the record has it and it is a `T`.
    pub fn get<T: Any>(&self, name: &str) -> Option<&T> {
        self.slots
            .iter()
            .find(|(have, _)| &**have == name)
            .and_then(|(_, slot)| slot.value.downcast_ref::<T>())
    }

    /// Remove the field `name` and return it as a `T`.
    ///
    /// # Errors
    ///
    /// [`PlanError::NotInValue`] if the record has no such field, and
    /// [`PlanError::FieldType`] if it is not a `T`, in which case the field
    /// stays in the record.
    pub fn take<T: Any>(&mut self, name: &str) -> Result<T, Error> {
        let slot = self.take_slot(name).ok_or_else(|| PlanError::NotInValue {
            field: name.to_owned(),
        })?;
        slot.downcast::<T>().map_err(|slot| {
            self.slots.push((Arc::from(name), slot));
            PlanError::FieldType {
                field: name.to_owned(),
                expected: type_name::<T>(),
            }
            .into()
        })
    }

    pub(crate) fn take_slot(&mut self, name: &str) -> Option<Slot> {
        let at = self.slots.iter().position(|(have, _)| &**have == name)?;
        Some(self.slots.remove(at).1)
    }

    /// Remove the field `name`, whatever it holds; whether there was one.
    pub fn remove(&mut self, name: &str) -> bool {
        self.take_slot(name).is_some()
    }

    /// Whether the record has a field `name`.
    pub fn contains(&self, name: &str) -> bool {
        self.slots.iter().any(|(have, _)| &**have == name)
    }

    /// The field names, in order.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.slots.iter().map(|(name, _)| &**name)
    }

    /// How many fields the record has.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the record has no fields.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

impl fmt::Debug for FieldValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, slot) in &self.slots {
            let _ = map.entry(&&**name, &slot.type_name());
        }
        map.finish()
    }
}

/// A record is itself a value a plan can take apart: a binding that builds
/// rows at run time, or a test, hands one to a fields plan directly. Every
/// field is read at whatever type the plan names, and refused at any other.
impl Fields for FieldValues {
    fn field_names(&self) -> Vec<&str> {
        self.names().collect()
    }
}

impl<F: Any> Field<F> for FieldValues {
    fn field(&self, name: &str) -> Option<&F> {
        self.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_replaces_a_field_in_place_and_keeps_order() {
        let mut values = FieldValues::new();
        values.insert("a", 1u32).insert("b", 2u32).insert("a", 3u32);
        assert_eq!(values.names().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(values.get::<u32>("a"), Some(&3));
        assert_eq!(values.len(), 2);
        assert!(!values.is_empty());
        assert!(FieldValues::new().is_empty());
    }

    #[test]
    fn take_refuses_a_missing_field_and_a_wrong_type_without_losing_it() {
        let mut values = FieldValues::new();
        values.insert("age", 34u32);
        assert!(matches!(
            values.take::<u32>("email"),
            Err(Error::Plan(PlanError::NotInValue { field })) if field == "email"
        ));
        assert!(matches!(
            values.take::<String>("age"),
            Err(Error::Plan(PlanError::FieldType { field, .. })) if field == "age"
        ));
        assert!(values.contains("age"), "a wrong-type take leaves the field");
        assert_eq!(values.take::<u32>("age").unwrap(), 34);
        assert!(!values.contains("age"), "a take removes the field");
        values.insert("age", 34u32);
        assert!(values.remove("age"));
        assert!(!values.remove("age"), "nothing left to remove");
        assert!(!values.contains("age"));
    }

    #[test]
    fn debug_shows_names_and_types_never_values() {
        let mut values = FieldValues::new();
        values.insert("secret", String::from("hunter2"));
        let shown = format!("{values:?}");
        assert_eq!(shown, r#"{"secret": "alloc::string::String"}"#);
    }

    #[test]
    fn a_record_reads_its_fields_at_the_type_asked_for() {
        let mut values = FieldValues::new();
        values.insert("age", 34u32);
        assert_eq!(values.field_names(), ["age"]);
        assert_eq!(Field::<u32>::field(&values, "age"), Some(&34));
        assert_eq!(Field::<u64>::field(&values, "age"), None);
        assert_eq!(FieldValues::schema(), None);
    }

    #[test]
    fn a_schema_entry_reports_its_name_and_type() {
        let schema = FieldSchema::of::<u32>("age");
        assert_eq!(schema.name(), "age");
        assert_eq!(schema.type_id(), TypeId::of::<u32>());
        assert_eq!(schema.type_name(), "u32");
    }
}

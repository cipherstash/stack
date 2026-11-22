//! The record of named values a plan that is data produces and reads
//! ([`FieldValues`]). Internal to the dynamic path.
use std::any::{type_name, Any};
use std::fmt;
use std::sync::Arc;

use super::PlanError;
use crate::Error;

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

    /// Whether the value is a `T`.
    pub(crate) fn is<T: Any>(&self) -> bool {
        self.value.is::<T>()
    }

    pub(crate) fn type_name(&self) -> &'static str {
        self.type_name
    }
}

/// A record of named fields: what a plan that is data produces when it
/// encrypts a record, and what it reads when it decrypts one. Each field
/// holds the type its declaration produces, and is read back by name and
/// type.
///
/// Its [`Debug`](fmt::Debug) shows each field's name and type, never a
/// value: a decrypted record holds plaintext.
#[derive(Default)]
pub(crate) struct FieldValues {
    slots: Vec<(Arc<str>, Slot)>,
}

impl FieldValues {
    /// An empty record.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn from_slots(slots: Vec<(Arc<str>, Slot)>) -> Self {
        Self { slots }
    }

    /// Set the field `name` to `value`, replacing any value it had.
    pub(crate) fn insert<T: Any + Send>(&mut self, name: &str, value: T) -> &mut Self {
        let slot = Slot::new(value);
        match self.slots.iter_mut().find(|(have, _)| &**have == name) {
            Some((_, existing)) => *existing = slot,
            None => self.slots.push((Arc::from(name), slot)),
        }
        self
    }

    /// The field `name`, if the record has it and it is a `T`.
    pub(crate) fn get<T: Any>(&self, name: &str) -> Option<&T> {
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
    pub(crate) fn take<T: Any>(&mut self, name: &str) -> Result<T, Error> {
        let at = self
            .slots
            .iter()
            .position(|(have, _)| &**have == name)
            .ok_or_else(|| PlanError::NotInValue {
                field: name.to_owned(),
            })?;
        let (name, slot) = self.slots.remove(at);
        slot.downcast::<T>().map_err(|slot| {
            // Back where it was: the record keeps its order.
            self.slots.insert(at, (Arc::clone(&name), slot));
            PlanError::FieldType {
                field: name.to_string(),
                expected: type_name::<T>(),
            }
            .into()
        })
    }

    pub(crate) fn take_slot(&mut self, name: &str) -> Option<Slot> {
        let at = self.slots.iter().position(|(have, _)| &**have == name)?;
        Some(self.slots.remove(at).1)
    }

    pub(crate) fn slot(&self, name: &str) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|(have, _)| &**have == name)
            .map(|(_, slot)| slot)
    }

    /// Whether the record has a field `name`.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.slots.iter().any(|(have, _)| &**have == name)
    }

    /// The field names, in order.
    pub(crate) fn names(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.slots.iter().map(|(name, _)| &**name)
    }
}

/// Let go of every field. A record a data plan encrypts holds its fields as
/// [`ValueFrame`](crate::dynamic::ValueFrame)s, which keep their bytes under
/// `Protected` and wipe them as they drop. So clearing the record wipes
/// each field once.
impl zeroize::Zeroize for FieldValues {
    fn zeroize(&mut self) {
        self.slots.clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_replaces_a_field_in_place_and_keeps_order() {
        let mut values = FieldValues::new();
        values.insert("a", 1u32).insert("b", 2u32).insert("a", 3u32);
        assert_eq!(values.names().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(values.get::<u32>("a"), Some(&3));
        assert_eq!(FieldValues::new().names().count(), 0);
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
        values.insert("email", String::from("e"));
        assert!(values.take::<String>("age").is_err());
        assert_eq!(
            values.names().collect::<Vec<_>>(),
            ["age", "email"],
            "a wrong-type take leaves the field where it was"
        );
        assert!(values.take_slot("email").is_some());
        assert_eq!(values.take::<u32>("age").unwrap(), 34);
        assert!(!values.contains("age"), "a take removes the field");
        values.insert("age", 34u32);
        assert!(values.take_slot("age").is_some());
        assert!(values.take_slot("age").is_none(), "nothing left to take");
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
        assert_eq!(values.get::<u32>("age"), Some(&34));
        assert_eq!(values.get::<u64>("age"), None);
    }
}

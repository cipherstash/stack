//! How a field verb names its field: by name, read through the value's
//! [`Field<F>`], or by a **picker**, a name with an accessor that reads the
//! field directly.
use std::sync::Arc;

use super::values::{Field, FieldSchema, Fields};

/// A field verb's field argument: a name, or a picker.
///
/// - `"email"`: the field is read through the value's [`Field<F>`] impl,
///   looked up by name, which is what a dynamic value (a binding's
///   `FfiValue`) provides. The value names its fields
///   ([`Fields::field_names`]), so a fields plan checks them against its own
///   in both directions every time it runs.
/// - `("email", accessor)`: a **picker**. The accessor reads the field out
///   of a borrowed value, and its return type is the field's type, so the
///   verb needs no turbofish and the value needs no `Fields` or `Field<F>`
///   impl. The type check is the compiler's. This is the form the derive
///   emits.
///
/// The accessor is any `for<'b> Fn(&'b S) -> &'b F`: a function item, a
/// function pointer, or a closure whose signature is fixed where it is
/// written. Rust does not infer a higher-ranked signature for a closure
/// written straight into a tuple (`("email", |u: &User| &u.email)` is
/// refused with "lifetime may not live long enough"), so write the picker
/// with [`pick`], which fixes it:
///
/// ```
/// use stack_encrypt::plan::pick;
/// # struct User { email: String }
/// let email = pick("email", |u: &User| &u.email);
/// # let _ = email;
/// ```
///
/// A plan built only from pickers never asks the value for its field names:
/// the plan names exactly the fields its accessors read, and a value's
/// other fields are not its concern. A plan that names any field by name
/// checks the value against every field it declares.
///
/// Sealed: the two forms are the whole grammar.
pub trait FieldRef<S, F>: sealed::Sealed<S, F> {
    /// The field's name: its key in the record, and its identity unless one
    /// is pinned.
    fn name(&self) -> &str;
}

/// A picker: the field `name`, read by `accessor`. The same as writing the
/// tuple `(name, accessor)`, with the accessor's signature fixed so a
/// closure borrowing from its argument compiles.
///
/// ```
/// # use stack_encrypt::plan::{pick, FieldRef};
/// # struct User { email: String }
/// let email = pick("email", |u: &User| &u.email);
/// assert_eq!(FieldRef::<User, String>::name(&email), "email");
/// ```
pub fn pick<S, F, G>(name: &str, accessor: G) -> (&str, G)
where
    G: for<'b> Fn(&'b S) -> &'b F,
{
    (name, accessor)
}

/// Read a field out of a value: by name or by accessor.
pub(crate) type Reader<S, F> = Arc<dyn for<'b> Fn(&'b S) -> Option<&'b F> + Send + Sync>;

/// A value's own account of its fields, captured where a verb named a field
/// by name (and so `S: Field<F>`, whose supertrait is [`Fields`]).
pub(crate) struct FieldsOf<S> {
    pub(crate) names: for<'b> fn(&'b S) -> Vec<&'b str>,
    pub(crate) schema: fn() -> Option<Vec<FieldSchema>>,
}

impl<S> Clone for FieldsOf<S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S> Copy for FieldsOf<S> {}

mod sealed {
    use super::{FieldsOf, Reader};

    /// What a field argument resolves to. Unnameable outside the crate.
    pub struct Access<S, F> {
        pub(crate) read: Reader<S, F>,
        pub(crate) fields: Option<FieldsOf<S>>,
    }

    pub trait Sealed<S, F> {
        fn access(self) -> Access<S, F>;
    }
}
pub(crate) use sealed::Access;

impl<S: Field<F>, F: 'static> FieldRef<S, F> for &str {
    fn name(&self) -> &str {
        self
    }
}
impl<S: Field<F>, F: 'static> sealed::Sealed<S, F> for &str {
    fn access(self) -> Access<S, F> {
        let name: Arc<str> = Arc::from(self);
        Access {
            read: Arc::new(move |source: &S| source.field(&name)),
            fields: Some(FieldsOf {
                names: <S as Fields>::field_names,
                schema: <S as Fields>::schema,
            }),
        }
    }
}

impl<S, F, G> FieldRef<S, F> for (&str, G)
where
    G: for<'b> Fn(&'b S) -> &'b F + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        self.0
    }
}
impl<S, F, G> sealed::Sealed<S, F> for (&str, G)
where
    G: for<'b> Fn(&'b S) -> &'b F + Send + Sync + 'static,
{
    fn access(self) -> Access<S, F> {
        let accessor = self.1;
        Access {
            read: Arc::new(move |source: &S| Some(accessor(source))),
            fields: None,
        }
    }
}

/// The name and the access of a field argument, taken apart.
pub(crate) fn resolve<S, F>(field: impl FieldRef<S, F>) -> (Arc<str>, Access<S, F>) {
    let name = Arc::from(field.name());
    (name, sealed::Sealed::access(field))
}

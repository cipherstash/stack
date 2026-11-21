//! The label a plan's context is written as, and the label of each field
//! under it.
use crate::{Label, LabelError};

/// A context a plan is declared under: a [`Label`], or text parsed as one.
///
/// A plan's context is a name, so it is a label of plain segments:
/// `"users"`, or `"documents/v2/body"`, which is three segments and renders
/// in the ZeroKMS log exactly as written. Text that is not a plain label is
/// refused when the plan is parsed or run
/// ([`PlanError::ContextLabel`](super::PlanError::ContextLabel)).
pub trait IntoLabel {
    /// The label, or why the text is not one.
    fn into_label(self) -> Result<Label, LabelError>;
}
impl IntoLabel for Label {
    fn into_label(self) -> Result<Label, LabelError> {
        Ok(self)
    }
}
impl IntoLabel for &Label {
    fn into_label(self) -> Result<Label, LabelError> {
        Ok(self.clone())
    }
}
impl IntoLabel for &str {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(self)
    }
}
impl IntoLabel for String {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(&self)
    }
}
/// A context held in a `String` (a config value, say), borrowed.
impl IntoLabel for &String {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(self)
    }
}

/// Who supplied a context, for
/// [`PlanError::TwoContextSources`](super::PlanError::TwoContextSources).
#[cfg(feature = "dynamic")]
pub(crate) const FROM_PLAN: &str = "the plan";
#[cfg(feature = "dynamic")]
pub(crate) const FROM_CALL: &str = "the call";

/// The label a field is sealed under: the context, then its identity.
#[cfg(feature = "dynamic")]
pub(crate) fn join(context: &Label, identity: &str) -> Result<Label, LabelError> {
    Label::new(context.segments().chain([identity]))
}

/// The refusal of a field whose label is not plain.
#[cfg(feature = "dynamic")]
pub(crate) fn field_label(field: &str, source: LabelError) -> crate::Error {
    super::PlanError::FieldLabel {
        field: field.to_owned(),
        source,
    }
    .into()
}

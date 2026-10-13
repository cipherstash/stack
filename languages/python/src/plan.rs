//! The data plan from Python to the engine.
//!
//! Two jobs, and they are separate on purpose:
//!
//! 1. Walk the Python dict into an `FfiValue::Object`, the shape
//!    `dynamic::record::plan_with` parses.
//! 2. Resolve each field's `"target"` REQUEST into an EQL type name, through
//!    the engine's own resolver.
//!
//! The second is why this file exists rather than a generic dict converter.
//! Python writes `{"kind": "string", "index": "eq"}` — what the field holds
//! and what a query must do — and the engine answers `TextEq`. No EQL type
//! name is written in Python, which is principle G1 at the declaration layer.
//!
//! Everything else in the dict crosses unchanged. This file validates only
//! the target request; `plan_with` is what checks the context, the output
//! exclusivity, the type-admits-index rule and the rest, and its refusals
//! are better than any this could invent.

use pyo3::prelude::*;
use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyList, PyString};
use stack_encrypt::dynamic::{FfiValue, TargetDescriptor};

use crate::convert;
use crate::errors::PlanError;

/// A resolved target field: the EQL type and the two PostgreSQL domains the
/// caller needs to write its casts.
pub struct Resolved {
    pub field: String,
    pub name: String,
    pub sql_domain: String,
    pub query_sql_domain: Option<String>,
}

/// The wire plan, and what each target field resolved to.
///
/// The returned `FfiValue` carries `"target": "<EQL type name>"` where the
/// Python dict carried the request, because that is the grammar
/// `plan_with` parses.
pub fn resolve(fields: &Bound<'_, PyAny>) -> PyResult<(FfiValue, Vec<Resolved>)> {
    let fields = fields
        .cast::<PyDict>()
        .map_err(|_| PlanError::new_err("a plan is a dict of field name to field spec"))?;
    let mut entries: Vec<(String, FfiValue)> = Vec::with_capacity(fields.len());
    let mut resolved = Vec::new();

    for (key, value) in fields.iter() {
        let name = field_name(&key)?;
        let spec = value
            .cast::<PyDict>()
            .map_err(|_| PlanError::new_err(format!("{name}: a field spec is a dict")))?;
        let mut pairs: Vec<(String, FfiValue)> = Vec::with_capacity(spec.len());

        for (spec_key, spec_value) in spec.iter() {
            let spec_key = field_name(&spec_key)?;
            if spec_key == "target" {
                let target = target(&name, &spec_value)?;
                pairs.push((spec_key, FfiValue::String(target.name.clone().into())));
                resolved.push(Resolved {
                    field: name.clone(),
                    name: target.name,
                    sql_domain: target.sql_domain,
                    query_sql_domain: target.query_sql_domain,
                });
            } else {
                pairs.push((spec_key, plain(&spec_value)?));
            }
        }
        entries.push((name, FfiValue::Object(pairs)));
    }

    Ok((FfiValue::Object(entries), resolved))
}

/// One field's target request as a resolved descriptor.
///
/// Three spellings arrive here, and the function is idempotent over them so
/// a plan can be resolved more than once: `build()` resolves the request
/// dict to a NAME and stores that in `PlanSpec.fields`, and every engine
/// call parses those fields again. A bare string is therefore an
/// already-resolved name, and goes back through the resolver rather than
/// being trusted — a name that stopped being producible between `build()`
/// and the call is refused at the call.
fn target(field: &str, request: &Bound<'_, PyAny>) -> PyResult<TargetDescriptor> {
    if let Ok(name) = request.extract::<String>() {
        return crate::targets::named(&name)
            .map_err(|error| PlanError::new_err(format!("{field}: {error}")));
    }
    let request = request.cast::<PyDict>().map_err(|_| {
        PlanError::new_err(format!(
            "{field}: a target is an EQL type name, or a dict, either {{name}} or \
             {{kind, index}}"
        ))
    })?;

    if let Some(name) = request.get_item("name")? {
        let name = name
            .extract::<String>()
            .map_err(|_| PlanError::new_err(format!("{field}: an EQL type name is a string")))?;
        return crate::targets::named(&name)
            .map_err(|error| PlanError::new_err(format!("{field}: {error}")));
    }

    let kind = request
        .get_item("kind")?
        .ok_or_else(|| {
            PlanError::new_err(format!(
                "{field}: a target names an EQL type or declares a kind"
            ))
        })?
        .extract::<String>()
        .map_err(|_| PlanError::new_err(format!("{field}: a kind is a string")))?;
    let kind = convert::kind(&kind)?;

    let index = request
        .get_item("index")?
        .map(|value| value.extract::<String>())
        .transpose()
        .map_err(|_| PlanError::new_err(format!("{field}: an index is a string")))?;

    crate::targets::select(kind, index.as_deref())
        .map_err(|error| PlanError::new_err(format!("{field}: {error}")))
}

/// A plan value that is not a target: a string, or a list of strings and
/// integers.
///
/// The grammar's own vocabulary is narrow — a context is a string, bytes, an
/// integer or a list of those; `"outputs"` is a list of strings or of
/// option objects; `"type"` is a string — so this walks exactly that rather
/// than every Python type. A plan value the grammar does not use is refused
/// here with the key named, which reads better than `plan_with`'s
/// `Reason::UnknownKey` two layers down.
fn plain(value: &Bound<'_, PyAny>) -> PyResult<FfiValue> {
    if let Ok(list) = value.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(plain(&item)?);
        }
        return Ok(FfiValue::Array(items));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        // An index with options, as `"outputs"` spells them.
        let mut pairs = Vec::with_capacity(dict.len());
        for (key, inner) in dict.iter() {
            pairs.push((field_name(&key)?, plain(&inner)?));
        }
        return Ok(FfiValue::Object(pairs));
    }
    convert::to_ffi(value, None).map_err(Into::into)
}

/// A dict key as a plan name. Keys are field and spec names, so a non-string
/// key is a declaration defect rather than a value to encode.
fn field_name(key: &Bound<'_, PyAny>) -> PyResult<String> {
    key.cast::<PyString>()
        .map_err(|_| PlanError::new_err("a plan's keys are strings"))?
        .extract()
}

//! The layout Biome's formatter gives a JSON fixture, for the tests that
//! write one.

/// `value` as JSON text in the layout Biome's formatter gives a fixture
/// (`pnpm run code:check`), so a regenerated fixture is committed as
/// written. Two-space indent; a non-empty object puts each member on a line
/// of its own. An array with no object in it, at any depth, stays on one
/// line while that line, its trailing comma included, fits in 80 columns;
/// otherwise an array of numbers fills each line with as many numbers as
/// fit, and any other array, and always one holding an object, puts each
/// element on a line of its own, laid out by the same rule.
pub fn biome_json(value: &serde_json::Value) -> String {
    /// The value on one line, if it holds no object.
    fn inline(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::Object(map) if !map.is_empty() => None,
            serde_json::Value::Array(items) => Some(format!(
                "[{}]",
                items
                    .iter()
                    .map(inline)
                    .collect::<Option<Vec<_>>>()?
                    .join(", ")
            )),
            other => Some(text(other)),
        }
    }
    fn text(value: &serde_json::Value) -> String {
        serde_json::to_string(value).expect("JSON")
    }
    /// Write `value` starting at column `column`, inside `indent` spaces,
    /// with `tail` characters after it on its line.
    fn write(
        value: &serde_json::Value,
        indent: usize,
        column: usize,
        tail: usize,
        out: &mut String,
    ) {
        let pad = |n: usize| " ".repeat(n);
        match value {
            serde_json::Value::Object(map) if !map.is_empty() => {
                out.push_str("{\n");
                let last = map.len() - 1;
                for (i, (key, member)) in map.iter().enumerate() {
                    let key = format!("{}{}: ", pad(indent + 2), text(&key.as_str().into()));
                    out.push_str(&key);
                    let comma = usize::from(i != last);
                    write(member, indent + 2, key.chars().count(), comma, out);
                    if comma == 1 {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(indent));
                out.push('}');
            }
            serde_json::Value::Array(items) if !items.is_empty() => {
                if let Some(inline) = inline(value) {
                    if column + inline.chars().count() + tail <= 80 {
                        out.push_str(&inline);
                        return;
                    }
                }
                if items.iter().all(serde_json::Value::is_number) {
                    out.push_str("[\n");
                    let mut line = String::new();
                    for (i, item) in items.iter().enumerate() {
                        let item = text(item);
                        let comma = usize::from(i != items.len() - 1);
                        if !line.is_empty()
                            && indent + 2 + line.chars().count() + 1 + item.chars().count() + comma
                                > 80
                        {
                            out.push_str(&pad(indent + 2));
                            out.push_str(line.trim_end());
                            out.push('\n');
                            line.clear();
                        }
                        line.push_str(&item);
                        if comma == 1 {
                            line.push_str(", ");
                        }
                    }
                    out.push_str(&pad(indent + 2));
                    out.push_str(&line);
                    out.push('\n');
                    out.push_str(&pad(indent));
                    out.push(']');
                    return;
                }
                out.push_str("[\n");
                let last = items.len() - 1;
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&pad(indent + 2));
                    let comma = usize::from(i != last);
                    write(item, indent + 2, indent + 2, comma, out);
                    if comma == 1 {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(indent));
                out.push(']');
            }
            other => out.push_str(&text(other)),
        }
    }
    let mut out = String::new();
    write(value, 0, 0, 0, &mut out);
    out.push('\n');
    out
}

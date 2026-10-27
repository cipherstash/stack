//! The observed world: everything the database holds or is sent, parsed from
//! the wire form into one shape that the real scheme and the simulator both
//! produce. Every distinguisher reads an [`ObservedWorld`] and nothing else,
//! so it runs on the real and the simulated world unchanged.
//!
//! The parser takes the wire JSON, not the crate's types: the real side
//! serializes a sealed `JsonDocument` and each query term with `serde_json`,
//! the simulator writes the same JSON directly, and both go through
//! [`ObservedWorld::from_wire`]. A simulator that wrote a field the real form
//! lacks, or the other way round, shows in [`ObservedRow::fields`] and
//! [`ObservedEntry::fields`].
//!
//! A world is parsed in its stored and sent order. The distinguishers read
//! it in the canonical order ([`super::canonical`]), which keeps each
//! entry's stored slot beside it ([`ObservedRow::slots`]) and each query as
//! sent ([`ObservedWorld::sent`]).

use base64ct::{Base64, Encoding};
use serde_json::Value;

use super::chain::{Tag16, Tag8};

/// The header `h`, at the byte offsets its frozen layout gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedHeader {
    pub version: u8,
    pub flags: u8,
    pub epoch: [u8; 4],
    pub keyset: Tag16,
    pub iv: Tag16,
    pub tag: Vec<u8>,
    /// Bytes after the tag its length field promises: none in a well-formed
    /// header.
    pub trailing: usize,
}

/// One entry of `sv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedEntry {
    pub s: Tag16,
    pub c: Vec<u8>,
    /// The self tag. Every real entry carries one; `None` only from a
    /// mutant, and then [`ObservedEntry::fields`] shows it.
    pub x: Option<Tag8>,
    pub p: Option<Tag8>,
    pub op: Option<Vec<u8>>,
    /// The entry's wire keys.
    pub fields: Vec<String>,
    /// The entry's length in characters, as compact JSON.
    pub chars: usize,
}

/// One group of a projection: a stored `q`, or a needle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedGroup {
    pub pairs: Vec<(Tag16, Tag16)>,
    pub elements: Vec<ObservedGroup>,
}

/// One stored row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRow {
    /// The document's wire keys.
    pub fields: Vec<String>,
    /// The document's length in characters, as compact JSON.
    pub chars: usize,
    pub header: ObservedHeader,
    pub entries: Vec<ObservedEntry>,
    /// The slot in `sv` each entry is stored at: `0, 1, 2, …` as parsed,
    /// and wherever the canonical order took each entry from after
    /// [`super::canonical::canonical`].
    pub slots: Vec<usize>,
    pub q: ObservedGroup,
    /// Every key path inside `q` ([`key_paths`]).
    pub q_fields: Vec<String>,
}

/// Which SQL surface a query term was sent to. The database knows which
/// function it is evaluating, so the kind is part of what it observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueryKind {
    /// `->`, `json_tree_path_query`: a selector.
    Extract,
    /// `json_tree_subtree(doc, tokens, budget)`: a list of tokens and the
    /// budget.
    Subtree,
    /// `@>`: a containment needle, with its `alt`.
    Contains,
    /// `AtPath<Eq>`: a containment needle with no `alt`.
    Equals,
    /// `AtPath<Gte>`: a selector and an ordering term.
    Order,
}

/// One query term, as the database receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedQuery {
    Extract {
        s: Tag16,
    },
    Subtree {
        tokens: Vec<Tag16>,
        budget: u32,
    },
    Contains {
        needle: ObservedGroup,
        alt: Option<ObservedGroup>,
    },
    Equals {
        needle: ObservedGroup,
    },
    Order {
        s: Tag16,
        op: Vec<u8>,
    },
}

/// The column as the database sees it: its rows, then the query terms it was
/// sent, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedWorld {
    pub rows: Vec<ObservedRow>,
    pub queries: Vec<ObservedQuery>,
    /// The query terms with their lists in the order they were sent: the
    /// same as `queries` as parsed, and kept as they were after
    /// [`super::canonical::canonical`] puts the needles in `queries` in the
    /// canonical order.
    pub sent: Vec<ObservedQuery>,
    /// Every key path inside each query term's wire form ([`key_paths`]),
    /// which the parser above reads only in part.
    pub query_fields: Vec<Vec<String>>,
}

impl ObservedWorld {
    /// Parse a world from its wire form: each row as its stored JSON, each
    /// query as the JSON its term serializes to.
    pub fn from_wire(rows: &[Value], queries: &[(QueryKind, Value)]) -> Self {
        let parsed: Vec<ObservedQuery> = queries.iter().map(|(kind, q)| query(*kind, q)).collect();
        Self {
            rows: rows.iter().map(row).collect(),
            sent: parsed.clone(),
            queries: parsed,
            query_fields: queries.iter().map(|(_, q)| key_paths(q)).collect(),
        }
    }
}

fn b64(text: &Value) -> Vec<u8> {
    let text = text.as_str().expect("a base64 field is a string");
    Base64::decode_vec(text).expect("padded standard base64")
}

fn b64_16(text: &Value) -> Tag16 {
    b64(text).try_into().expect("a sixteen-byte tag")
}

fn b64_8(text: &Value) -> Tag8 {
    b64(text).try_into().expect("an eight-byte tag")
}

/// Every key path in `value`, sorted: `k` for a key at the top, `k.j` below
/// it, and `k[].j` below an array's elements. What a field the parser does
/// not read would show in.
pub fn key_paths(value: &Value) -> Vec<String> {
    fn walk(value: &Value, at: &str, out: &mut std::collections::BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let path = if at.is_empty() {
                        key.clone()
                    } else {
                        format!("{at}.{key}")
                    };
                    let _ = out.insert(path.clone());
                    walk(child, &path, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, &format!("{at}[]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    walk(value, "", &mut out);
    out.into_iter().collect()
}

fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

fn header(bytes: &[u8]) -> ObservedHeader {
    assert!(bytes.len() >= 40, "a header holds its fixed fields");
    let tag_len = usize::from(u16::from_le_bytes([bytes[38], bytes[39]]));
    assert!(
        bytes.len() >= 40 + tag_len,
        "a header holds the tag it promises"
    );
    ObservedHeader {
        version: bytes[0],
        flags: bytes[1],
        epoch: bytes[2..6].try_into().unwrap(),
        keyset: bytes[6..22].try_into().unwrap(),
        iv: bytes[22..38].try_into().unwrap(),
        tag: bytes[40..40 + tag_len].to_vec(),
        trailing: bytes.len() - 40 - tag_len,
    }
}

fn entry(value: &Value) -> ObservedEntry {
    ObservedEntry {
        s: b64_16(&value["s"]),
        c: base85_simd::decode(value["c"].as_str().expect("`c` is a string"))
            .expect("`c` is base85"),
        x: value.get("x").map(b64_8),
        p: value.get("p").map(b64_8),
        op: value.get("op").map(b64),
        fields: keys(value),
        chars: chars(value),
    }
}

/// A projection group, `{"sv": [{"s", "vs"}, …], "el": [group, …]}`.
pub fn group(value: &Value) -> ObservedGroup {
    ObservedGroup {
        pairs: value["sv"]
            .as_array()
            .expect("`sv` is a list")
            .iter()
            .map(|pair| (b64_16(&pair["s"]), b64_16(&pair["vs"])))
            .collect(),
        elements: value["el"]
            .as_array()
            .expect("`el` is a list")
            .iter()
            .map(group)
            .collect(),
    }
}

fn chars(value: &Value) -> usize {
    serde_json::to_string(value)
        .expect("a wire value serializes")
        .len()
}

fn row(value: &Value) -> ObservedRow {
    let entries: Vec<ObservedEntry> = value["sv"]
        .as_array()
        .expect("`sv` is a list")
        .iter()
        .map(entry)
        .collect();
    ObservedRow {
        fields: keys(value),
        chars: chars(value),
        header: header(&b64(&value["h"])),
        slots: (0..entries.len()).collect(),
        entries,
        q: group(&value["q"]),
        q_fields: key_paths(&value["q"]),
    }
}

fn query(kind: QueryKind, value: &Value) -> ObservedQuery {
    match kind {
        QueryKind::Extract => ObservedQuery::Extract { s: b64_16(value) },
        QueryKind::Subtree => ObservedQuery::Subtree {
            tokens: value["t"]
                .as_array()
                .expect("`t` is a list of tokens")
                .iter()
                .map(b64_16)
                .collect(),
            budget: value["budget"]
                .as_u64()
                .and_then(|b| u32::try_from(b).ok())
                .expect("the budget is an integer"),
        },
        QueryKind::Contains => ObservedQuery::Contains {
            needle: group(value),
            alt: value.get("alt").map(group),
        },
        QueryKind::Equals => {
            assert!(
                value.get("alt").is_none(),
                "an equality needle has no `alt`"
            );
            ObservedQuery::Equals {
                needle: group(value),
            }
        }
        QueryKind::Order => ObservedQuery::Order {
            s: b64_16(&value["s"]),
            op: b64(&value["op"]),
        },
    }
}

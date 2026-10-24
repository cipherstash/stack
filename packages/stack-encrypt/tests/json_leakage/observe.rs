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
    pub p: Option<Tag8>,
    pub op: Option<Vec<u8>>,
    /// The entry's wire keys.
    pub fields: Vec<String>,
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
    pub header: ObservedHeader,
    pub entries: Vec<ObservedEntry>,
    pub q: ObservedGroup,
}

/// Which SQL surface a query term was sent to. The database knows which
/// function it is evaluating, so the kind is part of what it observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QueryKind {
    /// `->`, `json_tree_path_query`: a selector.
    Extract,
    /// `json_tree_subtree`, `json_tree_subtree_at`: a token and gates.
    Subtree,
    /// `@>`: a containment needle, with its `alt`.
    Contains,
    /// `AtPath<Eq>`: a containment needle with no `alt`.
    Equals,
    /// `AtPath<Gte>`: a selector and an ordering term.
    Order,
}

/// One gate of a subtree read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedGate {
    Selector(Tag16),
    Slot(u32, Tag16),
}

/// One query term, as the database receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedQuery {
    Extract {
        s: Tag16,
    },
    Subtree {
        t: Tag16,
        gates: Vec<ObservedGate>,
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
}

impl ObservedWorld {
    /// Parse a world from its wire form: each row as its stored JSON, each
    /// query as the JSON its term serializes to.
    pub fn from_wire(rows: &[Value], queries: &[(QueryKind, Value)]) -> Self {
        Self {
            rows: rows.iter().map(row).collect(),
            queries: queries.iter().map(|(kind, q)| query(*kind, q)).collect(),
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
        p: value.get("p").map(b64_8),
        op: value.get("op").map(b64),
        fields: keys(value),
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

fn row(value: &Value) -> ObservedRow {
    ObservedRow {
        fields: keys(value),
        header: header(&b64(&value["h"])),
        entries: value["sv"]
            .as_array()
            .expect("`sv` is a list")
            .iter()
            .map(entry)
            .collect(),
        q: group(&value["q"]),
    }
}

fn gate(text: &Value) -> ObservedGate {
    let text = text.as_str().expect("a gate is a string");
    match text.strip_prefix('#') {
        Some(slot) => {
            let (n, selector) = slot.split_once(':').expect("`#n:<selector>`");
            ObservedGate::Slot(
                n.parse().expect("a position"),
                b64_16(&Value::String(selector.to_owned())),
            )
        }
        None => ObservedGate::Selector(b64_16(&Value::String(text.to_owned()))),
    }
}

fn query(kind: QueryKind, value: &Value) -> ObservedQuery {
    match kind {
        QueryKind::Extract => ObservedQuery::Extract { s: b64_16(value) },
        QueryKind::Subtree => ObservedQuery::Subtree {
            t: b64_16(&value["t"]),
            gates: value
                .get("g")
                .map(|g| {
                    g.as_array()
                        .expect("`g` is a list")
                        .iter()
                        .map(gate)
                        .collect()
                })
                .unwrap_or_default(),
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

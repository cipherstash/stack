//! Rust copies of the EQL functions that read a stored JSON document, for
//! tests and examples. Behind the `eql-simulator` feature.
//!
//! These functions copy what the database (EQL) does in PostgreSQL when
//! your app reads part of a [`JsonDocument`]. Production code does not use
//! them. In production, the database runs the EQL function and returns the
//! encrypted entries. The `eql-simulator` feature exists so that tests and
//! examples can read a document without PostgreSQL.
//!
//! Reading part of a stored document takes three steps:
//!
//! 1. Your app derives a token for the path to read, for example with
//!    [`KeysetCipher::json_subtree_key`](crate::KeysetCipher::json_subtree_key).
//!    The token tells the database which node to find.
//! 2. The database (EQL) runs an EQL function with that token, such as
//!    `eql_v4.json_tree_children`. The function returns the matching
//!    encrypted entries. The database never decrypts anything.
//! 3. Your app checks each entry and decrypts it. A subtree read checks
//!    its entries with [`JsonSubtreeKey::open`](crate::json::JsonSubtreeKey::open).
//!    A read of one level checks each entry with
//!    [`JsonSubtreeKey::open_child`](crate::json::JsonSubtreeKey::open_child).
//!
//! This module does step 2 in Rust. Each function copies one part of EQL:
//!
//! | Function | What it copies |
//! |---|---|
//! | [`json_tree_children`] | `eql_v4.json_tree_children` |
//! | [`json_tree_subtree`] | `eql_v4.json_tree_subtree`, with a budget of `0` |
//! | [`find_by_token`] | How the EQL functions find the entry a token names |
//! | [`entry_row`] | The row an EQL function returns for one entry |
//!
//! Turn the feature on in your dev-dependencies only, so that it stays out
//! of your production build:
//!
//! ```toml
//! [dev-dependencies]
//! stack-encrypt = { version = "0.4", features = ["eql-simulator"] }
//! ```
//!
//! This example reads the members of one object in a stored document:
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use serde_json::json;
//! use stack_encrypt::eql_simulator;
//! use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPath, JsonPlaintext};
//! use stack_encrypt::target::{AeadContext, CallerContext};
//! use stack_encrypt::{nonempty, DecryptFrom, EncryptInto, StackCipher};
//!
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let stored: JsonDocument = JsonPlaintext::from(json!({"tags": ["admin"]}))
//!     .encrypt_into_with_context(
//!         &keyset,
//!         CallerContext::from(nonempty!("users").with("profile")),
//!     )
//!     .await?;
//!
//! // Step 1, your app: derive the parent's key, which holds its token.
//! let parent = keyset
//!     .json_subtree_key(
//!         &JsonPath::parse("$.tags").unwrap(),
//!         &JsonOptions::default(),
//!         nonempty!("users").with("profile"),
//!     )
//!     .await?;
//!
//! // Step 2, the database. In production, this query returns the entries:
//! //   SELECT eql_v4.json_tree_children(profile, $1::text) FROM users WHERE id = $2
//! let token = &parent.token_bytes()[0];
//! let entries = eql_simulator::json_tree_children(&stored, token)
//!     .into_iter()
//!     .filter_map(|(slot, _, _)| eql_simulator::entry_row(&stored, slot));
//!
//! // Step 3, your app: check each entry against the parent, and decrypt it.
//! for entry in entries {
//!     let tag = JsonPlaintext::decrypt_from_with_context(
//!         parent.open_child(entry),
//!         &cipher,
//!         AeadContext::from(nonempty!("users").with("profile")),
//!     )
//!     .await?;
//!     assert_eq!(tag.value(), &json!("admin"));
//! }
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```

use crate::json::derive::{hit_token, parent_tag};
use crate::json::{JsonDocument, JsonEntry, JsonNode, Tag, MAX_DEPTH};

/// The entry whose token is `token`, with the slot it is stored at. `None`
/// when `token` names no node of the document.
///
/// Copies how the EQL functions find the node a token names. The database
/// matches the token's self tag (`eql_v4_internal.json_tree_self_tag`)
/// against the index `eql_v4_internal.json_tree_index` builds. EQL has no
/// function that returns this entry alone.
///
/// If several entries have the same self tag, this function returns the
/// last of them, as the index does. A sealed document never has two such
/// entries.
pub fn find_by_token<'d>(
    document: &'d JsonDocument,
    token: &Tag,
) -> Option<(usize, &'d JsonEntry)> {
    document.find(token)
}

/// The children of the node whose token is `token`: each child's slot,
/// entry, and token. Copies `eql_v4.json_tree_children`.
///
/// The children come in ordinal order, as the database returns them. That
/// puts an array's elements in index order, and an object's members in the
/// random order drawn when the document was sealed. The child's token is
/// `None` when the entry's self tag is neither a member's token nor an
/// element's token under this node. A token that names no node returns no
/// children.
///
/// Pass each slot to [`entry_row`] to get the row the database returns.
pub fn json_tree_children<'d>(
    document: &'d JsonDocument,
    token: &Tag,
) -> Vec<(usize, &'d JsonEntry, Option<Tag>)> {
    let iv = document.header().iv();
    let entries = document.entries();
    let mut children = Vec::new();
    if document.find(token).is_none() {
        return children;
    }
    // Probe the ordinals 0, 1, 2, … until one has no entry. A node has at
    // most as many children as the document has entries, so the loop ends
    // whatever the entries say.
    let most = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    for ordinal in 0..most {
        let wanted = parent_tag(iv, token, ordinal);
        // The last entry with the parent tag, as `find_by_token` picks.
        let Some((slot, entry)) = entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry.parent_tag() == Some(&wanted))
        else {
            break;
        };
        children.push((slot, entry, hit_token(iv, token, entry, ordinal)));
    }
    children
}

/// The node each token names, and every entry beneath it: each entry's
/// slot, the entry, and its depth below the node its token named. Copies
/// `eql_v4.json_tree_subtree(doc, tokens, 0)`. A budget of `0` reads the
/// whole subtree, whatever its size.
///
/// The rows come token by token, in the order of `tokens`. For each token,
/// the node comes first at depth `0`. After each entry come its own
/// children, in ordinal order. A token that names no node returns no rows.
///
/// The database returns one token's rows in slot order instead. Opening the
/// rows does not depend on their order.
///
/// A stored document can be forged, so its tags need not form a tree. This
/// function stops below the deepest level a sealed document has. The
/// function also stops after as many rows as the document has entries.
pub fn json_tree_subtree<'d>(
    document: &'d JsonDocument,
    tokens: &[Tag],
) -> Vec<(usize, &'d JsonEntry, u32)> {
    let mut rows = Vec::new();
    for token in tokens {
        let Some((slot, entry)) = document.find(token) else {
            continue;
        };
        let mut token_rows = vec![(slot, entry, 0)];
        walk(document, token, 1, &mut token_rows);
        rows.extend(token_rows);
    }
    rows
}

/// Appends the entries beneath the node whose token is `token` to `rows`,
/// each at its depth, starting at `depth` for the node's children.
fn walk<'d>(
    document: &'d JsonDocument,
    token: &Tag,
    depth: u32,
    rows: &mut Vec<(usize, &'d JsonEntry, u32)>,
) {
    // The walk returns each entry at most once in a tree. So when the tags
    // form a cycle, it stops once it has returned as many rows as the
    // document has entries. No sealed document nests deeper than
    // `MAX_DEPTH`, so a longer chain stops there, and the recursion stays
    // bounded.
    let most = document.entries().len();
    if rows.len() >= most || depth as usize > MAX_DEPTH {
        return;
    }
    for (slot, entry, child) in json_tree_children(document, token) {
        if rows.len() >= most {
            return;
        }
        rows.push((slot, entry, depth));
        if let Some(child) = child {
            walk(document, &child, depth + 1, rows);
        }
    }
}

/// The row an EQL function returns for the entry stored at `slot`: the
/// entry, with the document's header and the slot added. `None` when the
/// document has no entry at `slot`.
///
/// Copies `eql_v4_internal.json_tree_graft`. That function builds the row
/// for one entry. The `->` operator returns this row. The row has no depth (`d`).
/// `eql_v4.json_tree_children` and `eql_v4.json_tree_subtree` build the
/// same row and add the entry's depth.
pub fn entry_row(document: &JsonDocument, slot: usize) -> Option<JsonNode> {
    document
        .entries()
        .get(slot)
        .map(|entry| JsonNode::new(entry.clone(), document.header().clone(), slot as u64))
}

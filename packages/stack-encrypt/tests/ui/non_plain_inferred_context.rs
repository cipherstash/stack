use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

// A schema-qualified table is a natural thing to write, and it would render
// `b64:…/email`: the log would not name the table.
#[derive(EncryptFrom)]
#[stash(struct = User, context = "public/users")]
struct SchemaQualified {
    email: StackCipherText,
}

struct Reading(u32);

// A tuple index begins with a digit, which a descriptor reserves.
#[derive(EncryptFrom)]
#[stash(struct = Reading, context = "readings")]
struct EncryptedReading(StackCipherText);

fn main() {}

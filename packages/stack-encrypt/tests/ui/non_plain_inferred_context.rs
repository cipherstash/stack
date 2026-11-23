use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

// A schema-qualified table is a natural thing to write, and it would render
// `b64:…/email`: the log would not name the table.
#[derive(EncryptTarget)]
#[stash(struct = User, scope = "public/users")]
struct SchemaQualified {
    email: StackCipherText,
}

#[derive(zeroize::Zeroize)]
struct Reading(u32);

// A tuple index begins with a digit, which a descriptor reserves.
#[derive(EncryptTarget)]
#[stash(struct = Reading, scope = "readings")]
struct EncryptedReading(StackCipherText);

fn main() {}

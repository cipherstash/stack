//! The generated sink names each field's type in a public associated type,
//! so a field's type has to be at least as visible as the struct (E0446).
//! A type that should stay unreachable can be `pub` inside a private module.

mod inner {
    // Stack Encrypt's derives. stack-encrypt depends on this crate, so each
    // derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
    use stack_encrypt_derive::Decrypt;
    use stack_encrypt_derive::Encrypt;

    #[derive(Encrypt, Decrypt)]
    #[aead(crate = "::vitaminc_aead")]
    pub(crate) struct Private {
        a: u32,
    }

    #[derive(Encrypt, Decrypt)]
    #[aead(crate = "::vitaminc_aead")]
    pub struct Public {
        p: Private,
    }
}

fn main() {}

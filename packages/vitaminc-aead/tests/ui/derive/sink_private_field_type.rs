//! The generated sink names each field's type in a public associated type,
//! so a field's type has to be at least as visible as the struct (E0446).
//! A type that should stay unreachable can be `pub` inside a private module.

mod inner {
    use vitaminc_aead::typed::Decrypt;
    use vitaminc_aead::Plaintext;

    #[derive(Plaintext, Decrypt)]
    pub(crate) struct Private {
        a: u32,
    }

    #[derive(Plaintext, Decrypt)]
    pub struct Public {
        p: Private,
    }
}

fn main() {}

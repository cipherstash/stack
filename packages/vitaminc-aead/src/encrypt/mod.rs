use crate::{cipher::Cipher, Aad, IntoAad};
pub mod impls;

pub trait Encrypt {
    fn encrypt<C>(self, cipher: C) -> Result<C::Ok, C::Error>
    where
        Self: Sized,
        C: Cipher,
    {
        self.encrypt_with_aad(cipher, Aad::empty())
    }

    // TODO: Add encrypt_with_aad (this is what should get implemented most of the time)
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>;
}

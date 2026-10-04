use stack_encrypt::{EncryptFrom, KeysetCipher, Pending};
struct Target;
impl EncryptFrom<u32> for Target {
    type Context = ();
    // The old extension is deliberately not part of the declaration trait.
    fn encrypt_from<'a,K>(_: &u32, cipher: &'a KeysetCipher<'_,K>, _:())->Pending<'a,Self,K> {
        Pending::failed(cipher, stack_encrypt::Error::Aead)
    }
}
fn main() {}

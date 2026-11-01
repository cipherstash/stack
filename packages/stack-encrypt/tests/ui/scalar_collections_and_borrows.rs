fn unsupported<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>) {
    let _ = keyset.encrypt(vec![1i32, 2]);
    let _ = keyset.encrypt(vec![1u8, 2]);
    let _ = keyset.encrypt("borrowed plaintext");
}
fn main() {}

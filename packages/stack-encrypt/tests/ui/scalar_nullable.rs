fn unsupported<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>) {
    let _ = keyset.encrypt(Some(42i32));
    let _ = keyset.encrypt(None::<i32>);
}
fn main() {}

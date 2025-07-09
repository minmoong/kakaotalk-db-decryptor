use crate::android::constants::{PASSWORD_CHARS, SYMBOL_MAP};
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
use sha1::Sha1;

/// Gernates a salt for Password-Based Encryption (PBE), used to derive a key
pub fn generate_salt(user_id: u64, enc_type: usize) -> [u8; 16] {
    let salt_base_str = SYMBOL_MAP
        .get(enc_type)
        .filter(|s| !s.is_empty())
        .map(|prefix| format!("{prefix}{user_id}"))
        .unwrap_or_else(|| user_id.to_string());

    let mut salt = [0u8; 16];
    salt.iter_mut()
        .zip(salt_base_str.bytes())
        .for_each(|(dst, src)| *dst = src);

    salt
}

/// Derives a 256-bit key using the user_id and encryption type
pub fn derive_key(user_id: u64, enc_type: usize) -> [u8; 32] {
    let salt = generate_salt(user_id, enc_type);
    let password_str = std::str::from_utf8(&PASSWORD_CHARS).unwrap();

    derive_key_utf8::<Sha1>(password_str, &salt, Pkcs12KeyType::EncryptionKey, 2, 32)
        .unwrap()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_USER_ID: u64 = 430023384;
    const TEST_ENC_TYPE: usize = 31;

    #[test]
    fn generate_salt_test() {
        let salt = generate_salt(TEST_USER_ID, TEST_ENC_TYPE);

        assert_eq!(
            salt,
            [
                118, 101, 105, 108, 52, 51, 48, 48, 50, 51, 51, 56, 52, 0, 0, 0
            ]
        );
    }

    #[test]
    fn derive_key_test() {
        let key = derive_key(TEST_USER_ID, TEST_ENC_TYPE);

        assert_eq!(
            key,
            [
                131, 89, 153, 30, 225, 154, 237, 53, 182, 168, 180, 185, 99, 127, 112, 245, 23, 10,
                186, 88, 52, 250, 53, 209, 38, 134, 191, 168, 228, 88, 159, 93,
            ]
        )
    }
}

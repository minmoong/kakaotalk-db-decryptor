use crate::android::constants::IV_BYTES;
use crate::android::key::derive_key;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose};

pub type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Decrypts the given Base64-encoded encrypted string using the specified user_id and enc_type
///
/// # Parameters
/// - `encrypted`: A Base64-encoded string representing the encrypted data.
/// - `user_id`: The user ID retrieved from each data.
/// - `enc_type`: Encryption type retrieved from `enc` field inside the data's `v` object.
///
/// # Returns
/// Returns the decrypted plaintext as a `String`.
pub fn decrypt(encrypted: &str, user_id: u64, enc_type: usize) -> String {
    if encrypted.contains(char::is_whitespace) || encrypted == "{}" || encrypted == "[]" {
        return encrypted.to_string();
    }

    let key = derive_key(user_id, enc_type);

    let cipher = Aes256CbcDec::new(&key.into(), &IV_BYTES.into());

    let mut encrypted_bytes = general_purpose::STANDARD.decode(encrypted).unwrap();

    let decrypted_data = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted_bytes)
        .unwrap();

    String::from_utf8(decrypted_data.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SOURCE: &str = "LvMle6ZEiBzr6/D5B8gmMazw8UHnjoK+GKxFqPcPgSQ=";
    const TEST_USER_ID: u64 = 430023384;
    const TEST_ENC_TYPE: usize = 31;

    #[test]
    fn decrypt_funcional_test() {
        let decrypted = decrypt(TEST_SOURCE, TEST_USER_ID, TEST_ENC_TYPE);

        assert_eq!(decrypted, "테스트 메시지");
    }

    #[test]
    fn decrypt_edge_cases_test() {
        assert_eq!(decrypt("   ", 0, 0), "   ");
        assert_eq!(decrypt("{}", 0, 0), "{}");
        assert_eq!(decrypt("[]", 0, 0), "[]");
    }
}

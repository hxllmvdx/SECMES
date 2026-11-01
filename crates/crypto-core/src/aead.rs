//! AEAD на собственных блочных шифрах (RC6/Serpent): CTR + HMAC-SHA256,
//! Encrypt-then-MAC. Используется Double Ratchet'ом для шифрования сообщений —
//! спецификация допускает любую AEAD-схему.
//!
//! Формат выхода `seal`: IV(16) || ciphertext || tag(32).

use crate::cipher::CipherKind;
use crate::errors::CryptoError;

/// Длины производных ключей и элементов формата.
pub const ENC_KEY_LEN: usize = 32;
pub const MAC_KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const TAG_LEN: usize = 32;

/// Ключи, выводимые из message key через HKDF-SHA256.
pub struct AeadKeys {
    pub enc_key: [u8; ENC_KEY_LEN],
    pub mac_key: [u8; MAC_KEY_LEN],
}

/// HKDF-SHA256(mk, info="SECMES_AEAD") -> enc_key || mac_key.
pub fn derive_keys(message_key: &[u8; 32]) -> AeadKeys {
    todo!()
}

/// Зашифровать с аутентификацией: случайный IV, CTR(kind, enc_key, iv, plaintext),
/// tag = HMAC-SHA256(mac_key, ad || iv || ciphertext). Выход: iv || ct || tag.
pub fn seal(
    kind: CipherKind,
    message_key: &[u8; 32],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!()
}

/// Проверить tag (constant-time сравнение) и расшифровать.
pub fn open(
    kind: CipherKind,
    message_key: &[u8; 32],
    associated_data: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!()
}

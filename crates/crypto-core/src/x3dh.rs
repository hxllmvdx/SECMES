//! X3DH (Extended Triple Diffie-Hellman) поверх ручного ECDH из модуля `ecdh`.
//!
//! Протокол собирается из примитивов: ECDH — свой, подпись prekey — ed25519-dalek,
//! KDF — HKDF-SHA256. См. https://signal.org/docs/specifications/x3dh/

use crate::ecdh::{EcdhPrivateKey, EcdhPublicKey};
use crate::errors::CryptoError;

/// Длина общего секрета X3DH в байтах.
pub const X3DH_SECRET_LEN: usize = 32;

/// Долгоживущая идентичность пользователя: ECDH-пара + подписывающая пара Ed25519.
pub struct IdentityKeyPair {
    pub dh: EcdhPrivateKey,
    // pub signing: ed25519_dalek::SigningKey,
    // pub verifying: ed25519_dalek::VerifyingKey,
}

/// Подписанный среднесрочный prekey (меняется периодически, подписан identity key).
pub struct SignedPreKey {
    pub id: u32,
    pub key: EcdhPrivateKey,
    // pub signature: ed25519_dalek::Signature,
}

/// Одноразовый prekey.
pub struct OneTimePreKey {
    pub id: u32,
    pub key: EcdhPrivateKey,
}

/// Публичный бандл, который пользователь публикует на сервере.
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_key: EcdhPublicKey,
    // pub identity_verifying_key: ed25519_dalek::VerifyingKey,
    pub signed_prekey_id: u32,
    pub signed_prekey: EcdhPublicKey,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<(u32, EcdhPublicKey)>,
}

/// Результат X3DH: общий секрет + данные, которые инициатор шлёт ответчику
/// в первом сообщении (эфемерный ключ, какой OPK использован).
pub struct X3dhResult {
    pub shared_secret: [u8; X3DH_SECRET_LEN],
    pub ephemeral_public: EcdhPublicKey,
    pub used_one_time_prekey_id: Option<u32>,
}

/// Генерация identity key + signed prekey (с подписью) + пачки one-time prekeys.
pub fn generate_identity() -> Result<(IdentityKeyPair, SignedPreKey, Vec<OneTimePreKey>), CryptoError> {
    todo!()
}

/// Публикация бандла из сгенерированных ключей.
pub fn publish_bundle(
    _identity: &IdentityKeyPair,
    _signed_prekey: &SignedPreKey,
    _one_time_prekey: Option<&OneTimePreKey>,
) -> PreKeyBundle {
    todo!()
}

/// Сторона инициатора (Alice): верифицировать подпись signed prekey,
/// вычислить DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B),
/// DH4 = DH(EK_A, OPK_B) если OPK есть; SK = HKDF-SHA256(0xFF*32 || DH1||DH2||DH3[||DH4]).
pub fn initiate(_identity: &IdentityKeyPair, _bundle: &PreKeyBundle) -> Result<X3dhResult, CryptoError> {
    todo!()
}

/// Сторона ответчика (Bob): восстановить тот же SK из своих приватных ключей
/// и присланного эфемерного публичного ключа Alice.
pub fn respond(
    _identity: &IdentityKeyPair,
    _signed_prekey: &SignedPreKey,
    _one_time_prekey: Option<&OneTimePreKey>,
    _alice_identity_public: &EcdhPublicKey,
    _alice_ephemeral_public: &EcdhPublicKey,
) -> Result<[u8; X3DH_SECRET_LEN], CryptoError> {
    todo!()
}

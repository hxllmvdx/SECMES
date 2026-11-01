//! Double Ratchet по спецификации Signal:
//! https://signal.org/docs/specifications/doubleratchet/
//!
//! DH-ratchet — на ручном ECDH (`ecdh`), симметричные KDF-цепочки — HKDF-SHA256,
//! шифрование сообщений — AEAD на собственных шифрах (RC6/Serpent в CTR + HMAC-SHA256,
//! Encrypt-then-MAC). Стартовый общий секрет приходит из X3DH.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::cipher::CipherKind;
use crate::ecdh::{EcdhPrivateKey, EcdhPublicKey};
use crate::errors::CryptoError;

/// Максимум пропущенных сообщений в одной цепочке.
pub const MAX_SKIP: usize = 1000;
/// Максимум сохранённых ключей пропущенных сообщений.
pub const MAX_SKIPPED_KEYS: usize = 2000;

/// Заголовок сообщения: текущий публичный ratchet-ключ,
/// длина предыдущей цепочки (PN) и номер сообщения в цепочке (N).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub ratchet_public: Vec<u8>, // сериализованный EcdhPublicKey
    pub previous_chain_len: u32,
    pub message_number: u32,
}

/// Ключ пропущенного сообщения, индексируется (ratchet_pub, message_number).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SkippedKeyId {
    pub ratchet_public: Vec<u8>,
    pub message_number: u32,
}

/// Состояние Double Ratchet одной стороны секретного чата.
pub struct RatchetState {
    /// Наша текущая DH-пара (DHs в спеке).
    pub self_dh: EcdhPrivateKey,
    /// Последний известный публичный ratchet-ключ пира (DHr), None до первого входящего.
    pub peer_dh: Option<EcdhPublicKey>,
    /// Root key (RK).
    pub root_key: [u8; 32],
    /// Цепочка отправки (CKs), None пока не сделан первый ratchet-шаг.
    pub send_chain_key: Option<[u8; 32]>,
    /// Цепочка приёма (CKr).
    pub recv_chain_key: Option<[u8; 32]>,
    /// Число отправленных сообщений в текущей цепочке (Ns).
    pub send_count: u32,
    /// Число принятых сообщений в текущей цепочке (Nr).
    pub recv_count: u32,
    /// Длина предыдущей цепочки отправки (PN).
    pub prev_send_count: u32,
    /// Ключи пропущенных (out-of-order) сообщений.
    pub skipped_keys: HashMap<SkippedKeyId, [u8; 32]>,
    /// Шифр AEAD для сообщений, выбирается при создании чата.
    pub cipher: CipherKind,
}

impl RatchetState {
    /// Инициализация Alice (инициатор X3DH): сразу делается первый DH-ratchet
    /// шаг с публичным signed prekey Боба как стартовым DHr.
    /// RK = SK из X3DH; (RK, CKs) = KDF_RK(SK, DH(DHs_alice_new, SPK_bob)).
    pub fn init_alice(
        x3dh_shared_secret: [u8; 32],
        bob_signed_prekey_public: &EcdhPublicKey,
        cipher: CipherKind,
    ) -> Result<Self, CryptoError> {
        todo!()
    }

    /// Инициализация Боба: RK = SK из X3DH, DHs = его signed prekey,
    /// цепочки пустые — появятся после первого входящего ratchet-шага.
    pub fn init_bob(
        x3dh_shared_secret: [u8; 32],
        bob_signed_prekey: EcdhPrivateKey,
        cipher: CipherKind,
    ) -> Self {
        todo!()
    }

    /// KDF_RK: (новый RK, новый CK) = HKDF-SHA256(rk, dh_out, info="SECMES_RATCHET_RK").
    pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        todo!()
    }

    /// KDF_CK: (следующий CK, message key) = HMAC/HKDF-SHA256 от ck
    /// с двумя разными константами (0x01 для MK, 0x02 для следующего CK).
    pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        todo!()
    }

    /// Зашифровать сообщение: CKs,mk = KDF_CK(CKs); header + aead::seal(cipher, mk, header, pt).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), CryptoError> {
        todo!()
    }

    /// Расшифровать: если новый ratchet_public в header — сначала skip_message_keys
    /// до PN, затем DH-ratchet шаг (обновить DHr, (RK,CKr)=KDF_RK, новая пара DHs,
    /// (RK,CKs)=KDF_RK). Дальше skip до N и AEAD-расшифровка по mk.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        todo!()
    }

    /// Сохранить message keys пропущенных сообщений текущей приёмной цепочки
    /// до номера `until` (с проверками MAX_SKIP / MAX_SKIPPED_KEYS).
    pub fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        todo!()
    }

    /// Попытаться расшифровать ключом из skipped_keys (out-of-order сообщение).
    fn try_skipped_keys(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        todo!()
    }
}

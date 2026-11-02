use super::{BlockMode, ModeKind};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// ECB: каждый блок независим, состояния кроме буфера нет, IV не используется.
#[derive(Default)]
pub struct EcbMode {
    buf: Vec<u8>,
}

impl BlockMode for EcbMode {
    fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        if !iv.is_empty() {
            return Err(CryptoError::InvalidIvLength {
                expected: 0,
                got: iv.len(),
            });
        }
        Ok(())
    }

    fn step_encrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        cipher.encrypt_block(block);
    }

    fn step_decrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        cipher.decrypt_block(block);
    }
}

impl_block_api!(EcbMode, ModeKind::Ecb);

use super::{take_iv16, BlockMode, ModeKind};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// CBC: блок XOR предыдущий шифротекст (первый — с IV) перед шифрованием.
#[derive(Default)]
pub struct CbcMode {
    buf: Vec<u8>,
    prev: [u8; 16],
}

impl BlockMode for CbcMode {
    fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        self.prev = take_iv16(iv)?;
        Ok(())
    }

    fn step_encrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(block);
        self.prev.copy_from_slice(block);
    }

    fn step_decrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        let saved: [u8; 16] = block.try_into().unwrap();
        cipher.decrypt_block(block);
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= p;
        }
        self.prev = saved;
    }
}

impl_block_api!(CbcMode, ModeKind::Cbc);

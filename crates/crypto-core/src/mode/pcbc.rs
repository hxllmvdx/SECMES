use super::{take_iv16, BlockMode, ModeKind};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// PCBC: как CBC, но обратная связь = plaintext XOR ciphertext предыдущего блока.
#[derive(Default)]
pub struct PcbcMode {
    buf: Vec<u8>,
    prev: [u8; 16],
}

impl BlockMode for PcbcMode {
    fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        self.prev = take_iv16(iv)?;
        Ok(())
    }

    fn step_encrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        let pt: [u8; 16] = block.try_into().unwrap();
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(block);
        for i in 0..16 {
            self.prev[i] = pt[i] ^ block[i];
        }
    }

    fn step_decrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]) {
        let ct: [u8; 16] = block.try_into().unwrap();
        cipher.decrypt_block(block);
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= p;
        }
        for i in 0..16 {
            self.prev[i] = block[i] ^ ct[i];
        }
    }
}

impl_block_api!(PcbcMode, ModeKind::Pcbc);

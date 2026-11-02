use super::{take_iv16, ModeKind, StreamMode};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// OFB: гамма = E(регистр), обратная связь — сама гамма.
/// Шифрование и расшифровка идентичны.
#[derive(Default)]
pub struct OfbMode {
    reg: [u8; 16],
    ks: [u8; 16],
    ks_used: usize,
}

impl StreamMode for OfbMode {
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        self.reg = take_iv16(iv)?;
        Ok(())
    }

    fn keystream_next(&mut self, cipher: &dyn BlockCipher) -> [u8; 16] {
        let mut ks = self.reg;
        cipher.encrypt_block(&mut ks);
        self.reg = ks;
        ks
    }

    fn ks_buf(&self) -> [u8; 16] {
        self.ks
    }
    fn set_ks_buf(&mut self, ks: [u8; 16]) {
        self.ks = ks;
    }
    fn ks_used(&self) -> usize {
        self.ks_used
    }
    fn set_ks_used(&mut self, used: usize) {
        self.ks_used = used;
    }
}

impl_stream_api!(OfbMode, ModeKind::Ofb);

use super::{take_iv16, ModeKind, StreamMode};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// CFB: гамма = E(регистр), обратная связь —
/// шифротекст, произведённый на этом блоке гаммы.
#[derive(Default)]
pub struct CfbMode {
    reg: [u8; 16],
    ks: [u8; 16],
    ks_used: usize,
    fb: [u8; 16],
    fb_len: usize,
}

impl StreamMode for CfbMode {
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        self.reg = take_iv16(iv)?;
        self.fb_len = 0;
        Ok(())
    }

    fn keystream_next(&mut self, cipher: &dyn BlockCipher) -> [u8; 16] {
        let mut ks = self.reg;
        cipher.encrypt_block(&mut ks);
        ks
    }

    fn feedback_ct(&mut self, ct: &[u8]) {
        self.fb[self.fb_len..self.fb_len + ct.len()].copy_from_slice(ct);
        self.fb_len += ct.len();
        if self.fb_len == 16 {
            self.reg = self.fb;
            self.fb_len = 0;
        }
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

impl_stream_api!(CfbMode, ModeKind::Cfb);

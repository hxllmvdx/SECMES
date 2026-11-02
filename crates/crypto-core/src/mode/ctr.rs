use super::{take_iv16, ModeKind, StreamMode};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// CTR: гамма = E(counter), счётчик растёт на 1 каждый блок (big-endian).
#[derive(Default)]
pub struct CtrMode {
    counter: [u8; 16],
    ks: [u8; 16],
    ks_used: usize,
}

impl StreamMode for CtrMode {
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        self.counter = take_iv16(iv)?;
        Ok(())
    }

    fn keystream_next(&mut self, cipher: &dyn BlockCipher) -> [u8; 16] {
        let mut ks = self.counter;
        cipher.encrypt_block(&mut ks);
        for b in self.counter.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
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

impl_stream_api!(CtrMode, ModeKind::Ctr);

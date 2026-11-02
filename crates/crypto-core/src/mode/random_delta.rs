use super::{take_iv16, ModeKind, StreamMode};
use crate::{cipher::BlockCipher, errors::CryptoError};

/// RandomDelta: как CTR, но шаг счётчика — не 1, а дельта из IV.
/// IV (16 байт) делится пополам: первая половина — начальный счётчик
/// (дополнена нулями спереди до 16 байт), вторая — дельта (также дополнена
/// нулями спереди), каждый блок: counter = counter + delta (mod 2^128).
#[derive(Default)]
pub struct RandomDeltaMode {
    counter: u128,
    delta: u128,
    ks: [u8; 16],
    ks_used: usize,
}

impl StreamMode for RandomDeltaMode {
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        let iv = take_iv16(iv)?;
        let (first, second) = iv.split_at(8);
        self.counter = u128::from_be_bytes({
            let mut b = [0u8; 16];
            b[8..].copy_from_slice(first);
            b
        });
        self.delta = u128::from_be_bytes({
            let mut b = [0u8; 16];
            b[8..].copy_from_slice(second);
            b
        });
        Ok(())
    }

    fn keystream_next(&mut self, cipher: &dyn BlockCipher) -> [u8; 16] {
        let mut ks = self.counter.to_be_bytes();
        cipher.encrypt_block(&mut ks);
        self.counter = self.counter.wrapping_add(self.delta);
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

impl_stream_api!(RandomDeltaMode, ModeKind::RandomDelta);

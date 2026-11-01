use super::{Padding, PaddingKind};
use crate::errors::CryptoError;
use rand::Rng;

pub struct Iso10126Padding;

impl Padding for Iso10126Padding {
    fn kind(&self) -> PaddingKind {
        PaddingKind::Iso10126
    }
    fn apply(&self, block: &mut [u8], data_len: usize) -> Result<(), CryptoError> {
        if data_len > block.len() {
            return Err(CryptoError::InvalidInput);
        }
        let pad_len = block.len() - data_len;
        if pad_len == 0 {
            return Ok(());
        }
        let to_pad = block.len() - 1;
        let mut rng = rand::rng();
        rng.fill_bytes(&mut block[data_len..to_pad]);
        block[to_pad] = pad_len as u8;
        Ok(())
    }
    fn unpad(&self, block: &[u8]) -> Result<usize, CryptoError> {
        if block.is_empty() {
            return Err(CryptoError::InvalidPadding);
        }
        let pad_len = *block.last().unwrap() as usize;
        if pad_len == 0 || pad_len > block.len() {
            return Err(CryptoError::InvalidPadding);
        }
        Ok(block.len() - pad_len)
    }
}


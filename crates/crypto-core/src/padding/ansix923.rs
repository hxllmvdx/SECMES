use super::{Padding, PaddingKind};
use crate::errors::CryptoError;

pub struct AnsiX923Padding;

impl Padding for AnsiX923Padding {
    fn kind(&self) -> PaddingKind {
        PaddingKind::AnsiX923
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
        block[data_len..to_pad].fill(0);
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
        let data_len = block.len() - pad_len;
        if block[data_len..block.len() - 1].iter().any(|&b| b != 0) {
            return Err(CryptoError::InvalidPadding);
        }
        Ok(data_len)
    }
}


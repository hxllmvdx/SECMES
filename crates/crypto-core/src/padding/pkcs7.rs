use super::{Padding, PaddingKind};
use crate::errors::CryptoError;

pub struct Pkcs7Padding;

impl Padding for Pkcs7Padding {
    fn kind(&self) -> PaddingKind {
        PaddingKind::Pkcs7
    }
    fn apply(&self, block: &mut [u8], data_len: usize) -> Result<(), CryptoError> {
        if data_len > block.len() {
            return Err(CryptoError::InvalidInput);
        }
        let pad_len = block.len() - data_len;
        if pad_len == 0 {
            return Ok(());
        }
        block[data_len..].fill(pad_len as u8);
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
        if block[data_len..].iter().any(|&b| b != pad_len as u8) {
            return Err(CryptoError::InvalidPadding);
        }
        Ok(data_len)
    }
}


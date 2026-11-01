use super::{Padding, PaddingKind};
use crate::errors::CryptoError;

pub struct ZerosPadding;

impl Padding for ZerosPadding {
    fn kind(&self) -> PaddingKind {
        PaddingKind::Zeros
    }
    fn apply(&self, block: &mut [u8], data_len: usize) -> Result<(), CryptoError> {
        if data_len > block.len() {
            return Err(CryptoError::InvalidInput);
        }
        block[data_len..].fill(0);
        Ok(())
    }
    fn unpad(&self, block: &[u8]) -> Result<usize, CryptoError> {
        if block.is_empty() {
            return Err(CryptoError::InvalidPadding);
        }
        match block.iter().rposition(|&b| b != 0) {
            Some(pos) => Ok(pos + 1),
            None => Ok(0),
        }
    }
}


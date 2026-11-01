use super::{BlockMode, ModeKind};
use crate::{cipher::BlockCipher, errors::CryptoError, padding::Padding};

#[derive(Default)]
pub struct EcbMode {/* TODO: state: prev block, keystream и т.д. */}

impl BlockMode for EcbMode {
    fn kind(&self) -> ModeKind {
        ModeKind::Ecb
    }
    fn output_len(&self, _len: usize, _bs: usize, _p: &dyn Padding) -> usize {
        todo!()
    }
    fn start_encrypt(&mut self, _iv: &[u8]) -> Result<(), CryptoError> {
        todo!()
    }
    fn start_decrypt(&mut self, _iv: &[u8]) -> Result<(), CryptoError> {
        todo!()
    }
    fn encrypt_update(
        &mut self,
        _c: &dyn BlockCipher,
        _i: &[u8],
        _o: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        todo!()
    }
    fn decrypt_update(
        &mut self,
        _c: &dyn BlockCipher,
        _i: &[u8],
        _o: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        todo!()
    }
    fn encrypt_finish(
        &mut self,
        _c: &dyn BlockCipher,
        _p: &dyn Padding,
        _o: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        todo!()
    }
    fn decrypt_finish(
        &mut self,
        _c: &dyn BlockCipher,
        _p: &dyn Padding,
        _o: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        todo!()
    }
}

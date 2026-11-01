use crate::cipher::BlockCipher;
use crate::errors::CryptoError;
use crate::padding::Padding;

use cbc::CbcMode;
use cfb::CfbMode;
use ctr::CtrMode;
use ecb::EcbMode;
use ofb::OfbMode;
use pcbc::PcbcMode;
use random_delta::RandomDeltaMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModeKind {
    Ecb,
    Cbc,
    Pcbc,
    Cfb,
    Ofb,
    Ctr,
    RandomDelta,
}

pub trait BlockMode {
    fn kind(&self) -> ModeKind;

    fn output_len(&self, input_len: usize, block_size: usize, padding: &dyn Padding) -> usize;

    fn start_encrypt(&mut self, iv: &[u8]) -> Result<(), CryptoError>;
    fn start_decrypt(&mut self, iv: &[u8]) -> Result<(), CryptoError>;

    fn encrypt_update(
        &mut self,
        cipher: &dyn BlockCipher,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;
    fn decrypt_update(
        &mut self,
        cipher: &dyn BlockCipher,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;

    fn encrypt_finish(
        &mut self,
        cipher: &dyn BlockCipher,
        padding: &dyn Padding,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;
    fn decrypt_finish(
        &mut self,
        cipher: &dyn BlockCipher,
        padding: &dyn Padding,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError>;
}

pub fn create_mode(kind: ModeKind) -> Box<dyn BlockMode> {
    match kind {
        ModeKind::Ecb => Box::new(EcbMode::default()),
        ModeKind::Cbc => Box::new(CbcMode::default()),
        ModeKind::Pcbc => Box::new(PcbcMode::default()),
        ModeKind::Cfb => Box::new(CfbMode::default()),
        ModeKind::Ofb => Box::new(OfbMode::default()),
        ModeKind::Ctr => Box::new(CtrMode::default()),
        ModeKind::RandomDelta => Box::new(RandomDeltaMode::default()),
    }
}

pub mod cbc;
pub mod cfb;
pub mod ctr;
pub mod ecb;
pub mod ofb;
pub mod pcbc;
pub mod random_delta;


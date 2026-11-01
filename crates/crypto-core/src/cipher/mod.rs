use crate::errors::CryptoError;

pub mod rc6;
pub mod serpent;

pub const BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CipherKind {
    Rc6,
    Serpent,
}

pub trait BlockCipher: Send + Sync {
    fn name(&self) -> &'static str;
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
    fn key_len(&self) -> usize;

    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);

    fn validate_key(&self, key: &[u8]) -> Result<(), CryptoError>;
}

pub fn create_cipher(kind: CipherKind, key: &[u8]) -> Result<Box<dyn BlockCipher>, CryptoError> {
    match kind {
        CipherKind::Rc6 => Ok(Box::new(rc6::RC6::new(key)?)),
        CipherKind::Serpent => Ok(Box::new(serpent::Serpent::new(key)?)),
    }
}

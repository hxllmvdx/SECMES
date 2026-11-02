use std::io::{Read, Write};

use crate::cipher::BlockCipher;
use crate::errors::CryptoError;
use crate::mode::CipherMode;
use crate::padding::Padding;

pub trait ProgressSink: Send + Sync {
    fn report(&self, done_bytes: u64, total_bytes: u64);
}

pub trait CancellationToken: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

pub struct NeverCancels;
impl CancellationToken for NeverCancels {
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub struct ChunkEncryptor<'a> {
    cipher: &'a dyn BlockCipher,
    mode: Box<dyn CipherMode>,
    padding: Box<dyn Padding>,
    chunk_size: usize,
}

impl<'a> ChunkEncryptor<'a> {
    /// Заголовок, который пойдёт первым в шифротекст: [algo][mode][padding][IV].
    /// Получатель по нему настраивает дешифратор — самодостаточный файл.
    pub fn header(&self) -> Vec<u8> {
        todo!()
    }

    pub fn encrypt_stream<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
        progress: &dyn ProgressSink,
        cancel: &dyn CancellationToken,
    ) -> Result<(), CryptoError> {
        todo!()
    }
}

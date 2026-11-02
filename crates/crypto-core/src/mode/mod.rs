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

/// Слой 1: публичный контракт любого режима.
pub trait CipherMode: Send + Sync {
    fn kind(&self) -> ModeKind;

    fn output_len(&self, input_len: usize, block_size: usize, padding: &dyn Padding) -> usize {
        input_len + padding.pad_len(input_len, block_size)
    }

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

/// Слой 2: блочное семейство (ECB, CBC, PCBC).
pub trait BlockMode: CipherMode {
    fn buf(&mut self) -> &mut Vec<u8>;

    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError>;

    fn step_encrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]);
    fn step_decrypt(&mut self, cipher: &dyn BlockCipher, block: &mut [u8]);

    fn process(
        &mut self,
        cipher: &dyn BlockCipher,
        out: &mut Vec<u8>,
        decrypt: bool,
        hold_last: bool,
    ) {
        let bs = cipher.block_size();
        let mut n = self.buf().len() / bs * bs;
        if hold_last && n > 0 {
            n -= bs;
        }
        let mut take = self.buf().drain(..n).collect::<Vec<u8>>();
        for block in take.chunks_exact_mut(bs) {
            if decrypt {
                self.step_decrypt(cipher, block);
            } else {
                self.step_encrypt(cipher, block);
            }
        }
        out.extend_from_slice(&take);
    }
}

/// Слой 2': поточное семейство (CFB, OFB, CTR, RandomDelta).
pub trait StreamMode: CipherMode {
    fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError>;

    fn keystream_next(&mut self, cipher: &dyn BlockCipher) -> [u8; 16];

    fn feedback_ct(&mut self, _ct: &[u8]) {}

    fn ks_buf(&self) -> [u8; 16];
    fn set_ks_buf(&mut self, ks: [u8; 16]);
    fn ks_used(&self) -> usize;
    fn set_ks_used(&mut self, used: usize);

    fn process_stream(
        &mut self,
        cipher: &dyn BlockCipher,
        input: &[u8],
        out: &mut Vec<u8>,
        decrypt: bool,
    ) {
        let bs = cipher.block_size();
        let mut pos = 0;
        while pos < input.len() {
            if self.ks_used() == bs {
                let ks = self.keystream_next(cipher);
                self.set_ks_buf(ks);
                self.set_ks_used(0);
            }
            let ks = self.ks_buf();
            let used = self.ks_used();
            let take = (bs - used).min(input.len() - pos);

            let mut ct_chunk = [0u8; 16];
            for j in 0..take {
                let ct = input[pos + j] ^ ks[used + j];
                ct_chunk[j] = if decrypt { input[pos + j] } else { ct };
                out.push(ct);
            }
            self.feedback_ct(&ct_chunk[..take]);
            self.set_ks_used(used + take);
            pos += take;
        }
    }
}

/// Реализация `CipherMode` для блочного режима
macro_rules! impl_block_api {
    ($t:ty, $kind:expr) => {
        impl crate::mode::CipherMode for $t {
            fn kind(&self) -> crate::mode::ModeKind {
                $kind
            }

            fn start_encrypt(&mut self, iv: &[u8]) -> Result<(), crate::errors::CryptoError> {
                <Self as crate::mode::BlockMode>::set_iv(self, iv)?;
                self.buf().clear();
                Ok(())
            }

            fn start_decrypt(&mut self, iv: &[u8]) -> Result<(), crate::errors::CryptoError> {
                self.start_encrypt(iv)
            }

            fn encrypt_update(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                i: &[u8],
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                self.buf().extend_from_slice(i);
                self.process(c, o, false, false);
                Ok(())
            }

            fn decrypt_update(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                i: &[u8],
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                self.buf().extend_from_slice(i);
                self.process(c, o, true, true);
                Ok(())
            }

            fn encrypt_finish(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                p: &dyn crate::padding::Padding,
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                let bs = c.block_size();
                let rem = self.buf().len();
                let mut block = vec![0u8; bs];
                block[..rem].copy_from_slice(self.buf());
                p.apply(&mut block, rem)?;
                self.step_encrypt(c, &mut block);
                o.extend_from_slice(&block);
                self.buf().clear();
                Ok(())
            }

            fn decrypt_finish(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                p: &dyn crate::padding::Padding,
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                let bs = c.block_size();
                if self.buf().len() != bs {
                    return Err(crate::errors::CryptoError::InvalidCiphertextLength);
                }
                let mut block = std::mem::take(self.buf());
                self.step_decrypt(c, &mut block);
                let data_len = p.unpad(&block)?;
                o.extend_from_slice(&block[..data_len]);
                Ok(())
            }
        }
    };
}

/// Реализация `CipherMode` для поточного режима.
macro_rules! impl_stream_api {
    ($t:ty, $kind:expr) => {
        impl crate::mode::CipherMode for $t {
            fn kind(&self) -> crate::mode::ModeKind {
                $kind
            }

            fn output_len(
                &self,
                input_len: usize,
                _block_size: usize,
                _padding: &dyn crate::padding::Padding,
            ) -> usize {
                input_len
            }

            fn start_encrypt(&mut self, iv: &[u8]) -> Result<(), crate::errors::CryptoError> {
                <Self as crate::mode::StreamMode>::set_iv(self, iv)?;
                self.set_ks_used(crate::cipher::BLOCK_SIZE);
                Ok(())
            }

            fn start_decrypt(&mut self, iv: &[u8]) -> Result<(), crate::errors::CryptoError> {
                self.start_encrypt(iv)
            }

            fn encrypt_update(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                i: &[u8],
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                self.process_stream(c, i, o, false);
                Ok(())
            }

            fn decrypt_update(
                &mut self,
                c: &dyn crate::cipher::BlockCipher,
                i: &[u8],
                o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                self.process_stream(c, i, o, true);
                Ok(())
            }

            fn encrypt_finish(
                &mut self,
                _c: &dyn crate::cipher::BlockCipher,
                _p: &dyn crate::padding::Padding,
                _o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                Ok(())
            }

            fn decrypt_finish(
                &mut self,
                _c: &dyn crate::cipher::BlockCipher,
                _p: &dyn crate::padding::Padding,
                _o: &mut Vec<u8>,
            ) -> Result<(), crate::errors::CryptoError> {
                Ok(())
            }
        }
    };
}

/// Общая проверка длины IV для режимов, которым он нужен.
pub(crate) fn take_iv16(iv: &[u8]) -> Result<[u8; 16], CryptoError> {
    iv.try_into().map_err(|_| CryptoError::InvalidIvLength {
        expected: 16,
        got: iv.len(),
    })
}

pub fn create_mode(kind: ModeKind) -> Box<dyn CipherMode> {
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

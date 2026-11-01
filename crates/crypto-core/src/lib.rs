// Заглушки (todo!()) по всему крейту — убрать этот allow по мере реализации.
#![allow(unused_variables, unused_mut)]

pub mod aead;
pub mod chunker;
pub mod cipher;
pub mod ecdh;
pub mod errors;
pub mod mode;
pub mod padding;
pub mod ratchet;
pub mod x3dh;

pub use chunker::{CancellationToken, NeverCancels, ProgressSink};
pub use cipher::{create_cipher, BlockCipher, CipherKind, BLOCK_SIZE};
pub use ecdh::{CurveParams, EcPoint, Ecdh, EcdhPrivateKey, EcdhPublicKey};
pub use errors::CryptoError;
pub use mode::{create_mode, BlockMode, ModeKind};
pub use padding::{create_padding, Padding, PaddingKind};
pub use ratchet::{RatchetHeader, RatchetState};
pub use x3dh::{PreKeyBundle, X3dhResult};

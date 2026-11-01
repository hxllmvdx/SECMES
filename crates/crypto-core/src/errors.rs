#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid IV length: expected {expected} bytes, got {got}")]
    InvalidIvLength { expected: usize, got: usize },

    #[error("invalid input")]
    InvalidInput,

    #[error("ciphertext is not a multiple of the block size")]
    InvalidCiphertextLength,

    #[error("invalid padding")]
    InvalidPadding,

    #[error("diffie-hellman: {0}")]
    Dh(&'static str),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("message authentication failed")]
    AuthenticationFailed,

    #[error("operation was cancelled")]
    Cancelled,
}

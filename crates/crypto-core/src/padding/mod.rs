use crate::errors::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PaddingKind {
    Zeros,
    Pkcs7,
    AnsiX923,
    Iso10126,
}

pub trait Padding: Send + Sync {
    fn kind(&self) -> PaddingKind;

    /// Сколько байт дописать к данным длиной `data_len`, чтобы итог был
    /// кратен `block_size`. Всегда >= 1: при кратной длине добавляется
    /// целый блок — иначе при дешифровке нечего было бы снимать.
    fn pad_len(&self, data_len: usize, block_size: usize) -> usize {
        let rem = data_len % block_size;
        if rem == 0 {
            block_size
        } else {
            block_size - rem
        }
    }

    /// Дописывает паддинг в последний блок.
    ///
    /// Контракт: `block` — буфер последнего блока целиком, данные занимают
    /// `block[..data_len]`, паддинг записывается в `block[data_len..]`.
    /// `block.len()` равен размеру блока шифра, `block.len() - data_len`
    /// и есть длина паддинга (>= 1; вызывающий код при кратной длине данных
    /// обязан передать полностью свободный блок).
    fn apply(&self, block: &mut [u8], data_len: usize) -> Result<(), CryptoError>;

    /// Снимает паддинг с последнего расшифрованного блока и возвращает
    /// длину данных в нём. Битый паддинг — ошибка `CryptoError::InvalidPadding`
    /// (кроме Zeros: там паддинг неотличим от данных, unpad не валидирует).
    fn unpad(&self, block: &[u8]) -> Result<usize, CryptoError>;
}

pub fn create_padding(kind: PaddingKind) -> Box<dyn Padding> {
    match kind {
        PaddingKind::Zeros => Box::new(zeros::ZerosPadding),
        PaddingKind::Pkcs7 => Box::new(pkcs7::Pkcs7Padding),
        PaddingKind::AnsiX923 => Box::new(ansix923::AnsiX923Padding),
        PaddingKind::Iso10126 => Box::new(iso10126::Iso10126Padding),
    }
}

pub mod ansix923;
pub mod iso10126;
pub mod pkcs7;
pub mod zeros;

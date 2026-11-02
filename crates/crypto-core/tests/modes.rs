use crypto_core::cipher::BlockCipher;
use crypto_core::errors::CryptoError;
use crypto_core::mode::{create_mode, CipherMode, ModeKind};
use crypto_core::padding::{create_padding, PaddingKind};

/// Мок-шифр: «шифрование» = прибавить 1 к каждому байту блока.
/// Позволяет проверять логику режимов без настоящей криптографии.
struct PlusOneCipher;

impl BlockCipher for PlusOneCipher {
    fn name(&self) -> &'static str {
        "plus-one"
    }

    fn key_len(&self) -> usize {
        16
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        for b in block.iter_mut() {
            *b = b.wrapping_add(1);
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        for b in block.iter_mut() {
            *b = b.wrapping_sub(1);
        }
    }

    fn validate_key(&self, _key: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

const IV: [u8; 16] = [0x42; 16];

fn encrypt(mode: &mut Box<dyn CipherMode>, pt: &[u8], iv: &[u8]) -> Vec<u8> {
    let c = PlusOneCipher;
    let p = create_padding(PaddingKind::Pkcs7);
    mode.start_encrypt(iv).unwrap();
    let mut ct = Vec::new();
    mode.encrypt_update(&c, pt, &mut ct).unwrap();
    mode.encrypt_finish(&c, p.as_ref(), &mut ct).unwrap();
    ct
}

fn decrypt(mode: &mut Box<dyn CipherMode>, ct: &[u8], iv: &[u8]) -> Vec<u8> {
    let c = PlusOneCipher;
    let p = create_padding(PaddingKind::Pkcs7);
    mode.start_decrypt(iv).unwrap();
    let mut out = Vec::new();
    mode.decrypt_update(&c, ct, &mut out).unwrap();
    mode.decrypt_finish(&c, p.as_ref(), &mut out).unwrap();
    out
}

fn roundtrip(kind: ModeKind, pt: &[u8], iv: &[u8]) {
    let ct = encrypt(&mut create_mode(kind), pt, iv);
    let out = decrypt(&mut create_mode(kind), &ct, iv);
    assert_eq!(out, pt, "roundtrip failed for {:?}", kind);
}

#[test]
fn mode_factory_works() {
    for k in [
        ModeKind::Ecb,
        ModeKind::Cbc,
        ModeKind::Pcbc,
        ModeKind::Cfb,
        ModeKind::Ofb,
        ModeKind::Ctr,
        ModeKind::RandomDelta,
    ] {
        let m = create_mode(k);
        assert_eq!(m.kind(), k);
    }
}

#[test]
fn block_modes_roundtrip_all_lengths() {
    for kind in [ModeKind::Ecb, ModeKind::Cbc, ModeKind::Pcbc] {
        let iv: &[u8] = if kind == ModeKind::Ecb { &[] } else { &IV };
        for len in [0usize, 1, 15, 16, 17, 33, 100] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            roundtrip(kind, &pt, iv);
        }
    }
}

#[test]
fn stream_modes_roundtrip_all_lengths() {
    for kind in [ModeKind::Cfb, ModeKind::Ofb, ModeKind::Ctr, ModeKind::RandomDelta] {
        for len in [0usize, 1, 15, 16, 17, 33, 100] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            roundtrip(kind, &pt, &IV);
        }
    }
}

#[test]
fn stream_modes_preserve_length() {
    let pt = [7u8; 33];
    for kind in [ModeKind::Cfb, ModeKind::Ofb, ModeKind::Ctr, ModeKind::RandomDelta] {
        let ct = encrypt(&mut create_mode(kind), &pt, &IV);
        assert_eq!(ct.len(), pt.len(), "{:?} must not add padding", kind);
    }
}

#[test]
fn ecb_equal_blocks_equal_ciphertext() {
    // суть ECB: одинаковые блоки plaintext -> одинаковый шифротекст
    let pt = [5u8; 32];
    let ct = encrypt(&mut create_mode(ModeKind::Ecb), &pt, &[]);
    assert_eq!(ct[..16], ct[16..32]);
}

#[test]
fn cbc_different_iv_different_ciphertext() {
    let pt = [5u8; 32];
    let iv2 = [0x43; 16];
    let ct1 = encrypt(&mut create_mode(ModeKind::Cbc), &pt, &IV);
    let ct2 = encrypt(&mut create_mode(ModeKind::Cbc), &pt, &iv2);
    assert_ne!(ct1, ct2);
    // но второй блок совпадать не должен тоже — цепочка разошлась
    assert_ne!(ct1[16..32], ct2[16..32]);
}

#[test]
fn ctr_zero_iv_known_keystream() {
    // мок: E(counter) = counter + 1 (по байтам). При IV = 0 первый блок
    // гаммы = [1; 16], второй (counter = 1) = [1,1,...,1,2] + 1 = [2;15..,3].
    let zero_iv = [0u8; 16];
    let pt = [0u8; 32];
    let ct = encrypt(&mut create_mode(ModeKind::Ctr), &pt, &zero_iv);
    assert_eq!(&ct[..16], &[1u8; 16]);
    let mut expected_second = [1u8; 16];
    expected_second[15] = 2; // counter = 0...01, байты +1
    assert_eq!(&ct[16..32], &expected_second);
}

#[test]
fn random_delta_zero_delta_repeats_keystream() {
    // delta = 0 => счётчик не меняется => гамма повторяется, как в ECB
    let zero_iv = [0u8; 16];
    let pt = [9u8; 32];
    let ct = encrypt(&mut create_mode(ModeKind::RandomDelta), &pt, &zero_iv);
    assert_eq!(ct[..16], ct[16..32]);
}

#[test]
fn random_delta_nonzero_delta_differs_from_ctr() {
    let pt = [0u8; 32];
    let mut iv = [0u8; 16];
    iv[15] = 3; // delta = 3
    let ct = encrypt(&mut create_mode(ModeKind::RandomDelta), &pt, &iv);
    // второй блок гаммы: counter = 3, E(counter) = +1 => последний байт 4
    assert_eq!(ct[31], 4);
}

#[test]
fn iv_length_validated() {
    let pt = [0u8; 16];
    let bad_iv = [0u8; 8];
    for kind in [ModeKind::Cbc, ModeKind::Cfb, ModeKind::Ctr] {
        let mut m = create_mode(kind);
        let c = PlusOneCipher;
        assert!(m.start_encrypt(&bad_iv).is_err());
        let _ = (&c, &pt); // silence
    }
}

#[test]
fn ecb_rejects_iv() {
    let mut m = create_mode(ModeKind::Ecb);
    assert!(m.start_encrypt(&IV).is_err());
    assert!(m.start_encrypt(&[]).is_ok());
}

#[test]
fn stream_modes_process_partial_chunks_across_updates() {
    // кормим по 5 байт — хвосты гаммы должны стыковаться между update
    let pt: Vec<u8> = (0..37u8).collect();
    let c = PlusOneCipher;
    let p = create_padding(PaddingKind::Pkcs7);

    let mut whole = create_mode(ModeKind::Ctr);
    whole.start_encrypt(&IV).unwrap();
    let mut ct_whole = Vec::new();
    whole.encrypt_update(&c, &pt, &mut ct_whole).unwrap();
    whole.encrypt_finish(&c, p.as_ref(), &mut ct_whole).unwrap();

    let mut chunked = create_mode(ModeKind::Ctr);
    chunked.start_encrypt(&IV).unwrap();
    let mut ct_chunked = Vec::new();
    for piece in pt.chunks(5) {
        chunked.encrypt_update(&c, piece, &mut ct_chunked).unwrap();
    }
    chunked.encrypt_finish(&c, p.as_ref(), &mut ct_chunked).unwrap();

    assert_eq!(ct_whole, ct_chunked);
}

#[test]
fn block_modes_process_partial_chunks_across_updates() {
    let pt: Vec<u8> = (0..53u8).map(|i| i.wrapping_mul(7)).collect();
    let c = PlusOneCipher;
    let p = create_padding(PaddingKind::Pkcs7);

    let mut whole = create_mode(ModeKind::Cbc);
    whole.start_encrypt(&IV).unwrap();
    let mut ct_whole = Vec::new();
    whole.encrypt_update(&c, &pt, &mut ct_whole).unwrap();
    whole.encrypt_finish(&c, p.as_ref(), &mut ct_whole).unwrap();

    let mut chunked = create_mode(ModeKind::Cbc);
    chunked.start_encrypt(&IV).unwrap();
    let mut ct_chunked = Vec::new();
    for piece in pt.chunks(7) {
        chunked.encrypt_update(&c, piece, &mut ct_chunked).unwrap();
    }
    chunked.encrypt_finish(&c, p.as_ref(), &mut ct_chunked).unwrap();

    assert_eq!(ct_whole, ct_chunked);

    let out = decrypt(&mut create_mode(ModeKind::Cbc), &ct_whole, &IV);
    assert_eq!(out, pt);
}

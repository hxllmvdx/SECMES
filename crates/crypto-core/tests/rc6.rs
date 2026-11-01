use crypto_core::cipher::rc6::RC6;
use crypto_core::cipher::BlockCipher;

fn hex(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn zero_vector_256bit_key() {
    let cipher = RC6::new(&[0u8; 32]).unwrap();
    let mut block = [0u8; 16];
    cipher.encrypt_block(&mut block);
    assert_eq!(
        block,
        hex("8f5fbd0510d15fa893fa3fda6e857ec2"),
        "encryption mismatch for all-zero key/block"
    );
    cipher.decrypt_block(&mut block);
    assert_eq!(block, [0u8; 16], "decryption must invert encryption");
}

#[test]
fn spec_vector_0123() {
    let key = {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&hex("0123456789abcdeffedcba9876543210"));
        k
    };
    let cipher = RC6::new(&key).unwrap();
    let mut block = hex("02132435465768798a9bacbdcedfe0f1");
    cipher.encrypt_block(&mut block);
    assert_eq!(block, hex("ba5816bfad855946484c7a1d3133ccf9"));
    cipher.decrypt_block(&mut block);
    assert_eq!(block, hex("02132435465768798a9bacbdcedfe0f1"));
}

#[test]
fn spec_vector_256bit_key() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let cipher = RC6::new(&key).unwrap();
    let mut block: [u8; 16] = std::array::from_fn(|i| i as u8);
    cipher.encrypt_block(&mut block);
    assert_eq!(
        block,
        hex("921c3ecd43d9426a90089334d67aea2e"),
        "encryption mismatch for 256-bit key"
    );
    cipher.decrypt_block(&mut block);
    assert_eq!(block, std::array::from_fn(|i| i as u8));
}

#[test]
fn roundtrip_random() {
    let mut state = 0x243F6A8885A308D3u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..100 {
        let mut key = [0u8; 32];
        let mut block = [0u8; 16];
        key.iter_mut().for_each(|b| *b = next() as u8);
        block.iter_mut().for_each(|b| *b = next() as u8);
        let original = block;

        let cipher = RC6::new(&key).unwrap();
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original, "ciphertext must differ from plaintext");
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original, "decrypt(encrypt(x)) != x");
    }
}

#[test]
fn rejects_bad_key_length() {
    assert!(RC6::new(&[0u8; 16]).is_err());
    assert!(RC6::new(&[0u8; 31]).is_err());
    assert!(RC6::new(&[0u8; 33]).is_err());
    assert!(RC6::new(&[0u8; 32]).is_ok());
}

#[test]
fn avalanche() {
    let cipher = RC6::new(&[0u8; 32]).unwrap();
    let mut base = [0u8; 16];
    cipher.encrypt_block(&mut base);

    let mut flipped = [0u8; 16];
    flipped[0] = 0x01; // отличается на 1 бит
    cipher.encrypt_block(&mut flipped);

    let diff = base
        .iter()
        .zip(flipped.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();
    assert!(
        (32..=96).contains(&diff),
        "avalanche effect too weak: {diff}/128 bits"
    );
}

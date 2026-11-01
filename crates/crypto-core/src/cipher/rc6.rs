use super::{BlockCipher, BLOCK_SIZE};
use crate::errors::CryptoError;

const P32: u32 = 0xB7E15163;
const Q32: u32 = 0x9E3779B9;
const ROUNDS: usize = 20;
const NUM_SUBKEYS: usize = 2 * ROUNDS + 4;

pub struct RC6 {
    s: [u32; NUM_SUBKEYS],
}

impl RC6 {
    pub const KEY_LEN: usize = 32;

    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != Self::KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            });
        }

        // Шаг 1: ключ (32 байта = 8 слов) little-endian
        let mut l = [0u32; Self::KEY_LEN / 4]; // L[0..8]
        for (i, w) in l.iter_mut().enumerate() {
            *w = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        // Шаг 2: инициализация S
        let mut s = [0u32; NUM_SUBKEYS];
        s[0] = P32;
        for i in 1..NUM_SUBKEYS {
            s[i] = s[i - 1].wrapping_add(Q32);
        }

        // Шаг 3: mixing, 3 * max(t, c) = 3 * 44 = 132 итерации
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        let mut i = 0usize;
        let mut j = 0usize;
        for _ in 0..3 * NUM_SUBKEYS.max(l.len()) {
            a = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
            s[i] = a;
            b = l[j]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(a.wrapping_add(b));
            l[j] = b;
            i = (i + 1) % NUM_SUBKEYS;
            j = (j + 1) % l.len();
        }

        Ok(Self { s })
    }

    #[inline]
    fn f(x: u32) -> u32 {
        // (x * (2x + 1)) <<< lg w, для w = 32 — сдвиг на 5
        x.wrapping_mul(x.wrapping_mul(2).wrapping_add(1))
            .rotate_left(5)
    }
}

impl BlockCipher for RC6 {
    fn name(&self) -> &'static str {
        "rc6"
    }

    fn key_len(&self) -> usize {
        Self::KEY_LEN
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), BLOCK_SIZE, "RC6 operates on 16-byte blocks");

        let mut a = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let mut b = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let mut c = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let mut d = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        // Прелюдия
        b = b.wrapping_add(self.s[0]);
        d = d.wrapping_add(self.s[1]);

        // 20 раундов
        for i in 1..=ROUNDS {
            let t = Self::f(b);
            let u = Self::f(d);

            a = (a ^ t).rotate_left(u);
            a = a.wrapping_add(self.s[2 * i]);

            c = (c ^ u).rotate_left(t);
            c = c.wrapping_add(self.s[2 * i + 1]);

            // поворот регистров (A, B, C, D) = (B, C, D, A)
            core::mem::swap(&mut a, &mut b);
            core::mem::swap(&mut b, &mut c);
            core::mem::swap(&mut c, &mut d);
        }

        // Постлюдия
        a = a.wrapping_add(self.s[42]);
        c = c.wrapping_add(self.s[43]);

        block[0..4].copy_from_slice(&a.to_le_bytes());
        block[4..8].copy_from_slice(&b.to_le_bytes());
        block[8..12].copy_from_slice(&c.to_le_bytes());
        block[12..16].copy_from_slice(&d.to_le_bytes());
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        assert_eq!(
            block.len(),
            BLOCK_SIZE,
            "block cipher operates on 16-byte blocks"
        );

        let mut a = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let mut b = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let mut c = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let mut d = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        // Обратная постлюдия
        c = c.wrapping_sub(self.s[43]);
        a = a.wrapping_sub(self.s[42]);

        // 20 раундов в обратном порядке
        for i in (1..=ROUNDS).rev() {
            // обратный поворот (A, B, C, D) = (D, A, B, C)
            core::mem::swap(&mut c, &mut d);
            core::mem::swap(&mut b, &mut c);
            core::mem::swap(&mut a, &mut b);

            let t = Self::f(b);
            let u = Self::f(d);

            c = c.wrapping_sub(self.s[2 * i + 1]);
            c = (c.rotate_right(t)) ^ u;

            a = a.wrapping_sub(self.s[2 * i]);
            a = (a.rotate_right(u)) ^ t;
        }

        // Обратная прелюдия
        d = d.wrapping_sub(self.s[1]);
        b = b.wrapping_sub(self.s[0]);

        block[0..4].copy_from_slice(&a.to_le_bytes());
        block[4..8].copy_from_slice(&b.to_le_bytes());
        block[8..12].copy_from_slice(&c.to_le_bytes());
        block[12..16].copy_from_slice(&d.to_le_bytes());
    }

    fn validate_key(&self, key: &[u8]) -> Result<(), CryptoError> {
        if key.len() == Self::KEY_LEN {
            Ok(())
        } else {
            Err(CryptoError::InvalidKeyLength {
                expected: Self::KEY_LEN,
                got: key.len(),
            })
        }
    }
}

use num_bigint::BigUint;
use rand::Rng;

use crate::errors::CryptoError;

/// Параметры кривой P-256: y^2 = x^3 + a*x + b (mod p), базовая точка G, порядок n.
pub struct CurveParams {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
    pub n: BigUint,
}

impl CurveParams {
    /// Константы P-256 (hex из `https://std.neuromancer.sk/nist/P-256/`).
    pub fn p256() -> Self {
        Self {
            p: BigUint::parse_bytes(
                b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                16,
            )
            .unwrap(),
            a: BigUint::parse_bytes(
                b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                16,
            )
            .unwrap(),
            b: BigUint::parse_bytes(
                b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                16,
            )
            .unwrap(),
            gx: BigUint::parse_bytes(
                b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                16,
            )
            .unwrap(),
            gy: BigUint::parse_bytes(
                b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                16,
            )
            .unwrap(),
            n: BigUint::parse_bytes(
                b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                16,
            )
            .unwrap(),
        }
    }
}

/// Точка на эллиптической кривой (аффинные координаты) или бесконечность.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcPoint {
    Infinity,
    Affine { x: BigUint, y: BigUint },
}

/// Публичный ключ ECDH — точка на кривой.
#[derive(Clone, Debug)]
pub struct EcdhPublicKey(pub EcPoint);

/// Приватный ключ ECDH — скаляр 1..n-1.
#[derive(Clone, Debug)]
pub struct EcdhPrivateKey {
    pub secret: BigUint,
    pub public: EcdhPublicKey,
}

pub struct Ecdh {
    pub curve: CurveParams,
}

impl Ecdh {
    pub fn p256() -> Self {
        Self {
            curve: CurveParams::p256(),
        }
    }

    // ---- арифметика конечного поля (mod p) ----

    pub fn field_add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.curve.p
    }

    pub fn field_sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        assert!(
            a < &self.curve.p && b < &self.curve.p,
            "field_sub: operands must be field elements (< p)"
        );
        (a + &self.curve.p - b) % &self.curve.p
    }

    pub fn field_mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.curve.p
    }

    pub fn field_inv(&self, a: &BigUint) -> BigUint {
        assert!(
            a % &self.curve.p != BigUint::from(0u8),
            "zero has no multiplicative inverse"
        );

        a.modpow(&(&self.curve.p - BigUint::new_const(2)), &self.curve.p)
    }

    // ---- операции над точками ----

    fn calc_x(&self, x1: &BigUint, x2: &BigUint, lambda: &BigUint) -> BigUint {
        self.field_sub(&self.field_sub(&self.field_mul(lambda, lambda), x1), x2)
    }

    fn calc_y(&self, x1: &BigUint, x3: &BigUint, y1: &BigUint, lambda: &BigUint) -> BigUint {
        self.field_sub(&self.field_mul(lambda, &self.field_sub(x1, x3)), y1)
    }

    pub fn point_add(&self, p1: &EcPoint, p2: &EcPoint) -> EcPoint {
        if p1.eq(&EcPoint::Infinity) {
            return p2.clone();
        } else if p2.eq(&EcPoint::Infinity) {
            return p1.clone();
        }

        let (x1, y1) = match p1 {
            EcPoint::Affine { x, y } => (x, y),
            _ => unreachable!(),
        };

        let (x2, y2) = match p2 {
            EcPoint::Affine { x, y } => (x, y),
            _ => unreachable!(),
        };

        if x1 == x2 {
            if y1 == y2 {
                return self.point_double(p1);
            } else {
                return EcPoint::Infinity;
            }
        }

        let lambda = self.field_mul(
            &self.field_sub(y2, y1),
            &self.field_inv(&self.field_sub(x2, x1)),
        );

        let x3 = self.calc_x(x1, x2, &lambda);
        let y3 = self.calc_y(x1, &x3, y1, &lambda);

        EcPoint::Affine { x: x3, y: y3 }
    }

    pub fn point_double(&self, p: &EcPoint) -> EcPoint {
        let (x, y) = match p {
            EcPoint::Affine { x, y } => (x, y),
            EcPoint::Infinity => return EcPoint::Infinity,
        };

        if *y == BigUint::ZERO {
            return EcPoint::Infinity;
        }

        let lambda = self.field_mul(
            &self.field_add(
                &self.field_mul(&self.field_mul(x, x), &BigUint::new_const(3)),
                &self.curve.a,
            ),
            &self.field_inv(&self.field_mul(y, &BigUint::new_const(2))),
        );

        let x3 = self.calc_x(x, x, &lambda);
        let y3 = self.calc_y(x, &x3, y, &lambda);

        EcPoint::Affine { x: x3, y: y3 }
    }

    /// Скалярное умножение k * P, double-and-add.
    pub fn scalar_mul(&self, k: &BigUint, point: &EcPoint) -> EcPoint {
        let mut res = EcPoint::Infinity;
        let mut q = point.clone();
        let mut count = k.clone();

        while count > BigUint::ZERO {
            if count.bit(0) {
                res = self.point_add(&res, &q);
            }

            q = self.point_double(&q);
            count >>= 1;
        }

        res
    }

    /// Проверка, что точка лежит на кривой (и не Infinity).
    pub fn is_on_curve(&self, point: &EcPoint) -> bool {
        match point {
            EcPoint::Infinity => false,
            EcPoint::Affine { x, y } => {
                if x >= &self.curve.p || y >= &self.curve.p {
                    return false;
                }

                let left = self.field_mul(y, y);

                let x_squared = self.field_mul(x, x);
                let x_cubed = self.field_mul(&x_squared, x);
                let ax = self.field_mul(&self.curve.a, x);
                let right = self.field_add(&self.field_add(&x_cubed, &ax), &self.curve.b);

                left == right
            }
        }
    }

    // ---- протокол ECDH ----

    /// Генерация пары ключей: случайный скаляр 1..n-1 (rejection sampling),
    /// публичный ключ = secret * G.
    pub fn generate_keypair(&self) -> Result<EcdhPrivateKey, CryptoError> {
        const MAX_ATTEMPTS: usize = 1024;

        let mut rng = rand::rng();
        let g = EcPoint::Affine {
            x: self.curve.gx.clone(),
            y: self.curve.gy.clone(),
        };

        for _ in 0..MAX_ATTEMPTS {
            let mut bytes = [0u8, 32];
            rng.fill_bytes(&mut bytes);

            let private_key = BigUint::from_bytes_be(&bytes);

            if private_key >= BigUint::ONE && private_key < self.curve.n {
                let public_key = self.scalar_mul(&private_key, &g);
                return Ok(EcdhPrivateKey {
                    secret: private_key,
                    public: EcdhPublicKey(public_key),
                });
            }
        }

        Err(CryptoError::Dh(
            "failed to generate keypair: rejection sampling exceeded attempt limit",
        ))
    }

    /// Общий секрет: x-координата (private.secret * peer_public), 32 байта.
    pub fn shared_secret(
        &self,
        private: &EcdhPrivateKey,
        peer_public: &EcdhPublicKey,
    ) -> Result<[u8; 32], CryptoError> {
        if !self.is_on_curve(&peer_public.0) {
            return Err(CryptoError::InvalidPublicKey);
        }

        let point = self.scalar_mul(&private.secret, &peer_public.0);
        let x = match point {
            EcPoint::Affine { x, .. } => x,
            EcPoint::Infinity => {
                return Err(CryptoError::Dh(
                    "got infinity point during calculation of shared_secret",
                ))
            }
        };

        let bytes = x.to_bytes_be();
        if bytes.len() > 32 {
            return Err(CryptoError::Dh("x is bigger than 32 bytes"));
        }

        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);

        Ok(padded)
    }

    // ---- сериализация (SEC1) ----

    /// 0x04 || X(32) || Y(32), всего 65 байт.
    pub fn serialize_public(&self, key: &EcdhPublicKey) -> Result<Vec<u8>, CryptoError> {
        let (x, y) = match &key.0 {
            EcPoint::Affine { x, y } => (x, y),
            EcPoint::Infinity => return Err(CryptoError::Dh("cannot serialize point at infinity")),
        };

        let x_bytes = x.to_bytes_be();
        let y_bytes = y.to_bytes_be();

        assert!(
            x_bytes.len() <= 32 && y_bytes.len() <= 32,
            "coordinates of a curve point must fit in 32 bytes"
        );

        let mut result = Vec::with_capacity(65);
        result.push(0x04);

        result.resize(33 - x_bytes.len(), 0);
        result.extend_from_slice(&x_bytes);

        result.resize(65 - y_bytes.len(), 0);
        result.extend_from_slice(&y_bytes);

        debug_assert_eq!(result.len(), 65);
        Ok(result)
    }

    /// Парсинг 65-байтового + валидация `is_on_curve`.
    pub fn deserialize_public(&self, bytes: &[u8]) -> Result<EcdhPublicKey, CryptoError> {
        if bytes.len() != 65 {
            return Err(CryptoError::Dh(
                "can't deserialize bytes, size is not equal to 65",
            ));
        }

        if bytes[0] != 0x04 {
            return Err(CryptoError::Dh(
                "bytes have invalid prefix, it's not equal to 0x04",
            ));
        }

        let point = EcPoint::Affine {
            x: BigUint::from_bytes_be(&bytes[1..33]),
            y: BigUint::from_bytes_be(&bytes[33..65]),
        };

        if !self.is_on_curve(&point) {
            return Err(CryptoError::InvalidPublicKey);
        }

        Ok(EcdhPublicKey(point))
    }
}

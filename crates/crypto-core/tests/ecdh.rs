//! Тесты ECDH (P-256).
//!
//! Главный — known-answer test из RFC 5903, секция 8.1 (256-Bit Random ECP
//! Group): фиксированные приватные ключи, эталонные публичные ключи и общий
//! секрет. Плюс roundtrip-проверки сериализации и отказ на битых входах.

use crypto_core::ecdh::{EcPoint, Ecdh, EcdhPrivateKey, EcdhPublicKey};
use crypto_core::errors::CryptoError;
use num_bigint::BigUint;

fn hex_big(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid hex")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// RFC 5903 §8.1 — приватный ключ инициатора.
const RFC_I: &str = "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433";
const RFC_GIX: &str = "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180";
const RFC_GIY: &str = "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3";

/// RFC 5903 §8.1 — приватный ключ респондента.
const RFC_R: &str = "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53";
const RFC_GRX: &str = "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63";
const RFC_GRY: &str = "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB";

/// RFC 5903 §8.1 — общий секрет (x-координата).
const RFC_GIRX: &str = "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE";

fn make_private(ecdh: &Ecdh, secret_hex: &str) -> EcdhPrivateKey {
    let secret = hex_big(secret_hex);
    let g = EcPoint::Affine {
        x: ecdh.curve.gx.clone(),
        y: ecdh.curve.gy.clone(),
    };
    let public = EcdhPublicKey(ecdh.scalar_mul(&secret, &g));
    EcdhPrivateKey { secret, public }
}

fn make_public(x_hex: &str, y_hex: &str) -> EcdhPublicKey {
    EcdhPublicKey(EcPoint::Affine {
        x: hex_big(x_hex),
        y: hex_big(y_hex),
    })
}

/// RFC 5903 §8.1: приватный ключ инициатора даёт эталонный публичный ключ.
#[test]
fn rfc5903_initiator_public_key() {
    let ecdh = Ecdh::p256();
    let private = make_private(&ecdh, RFC_I);
    let expected = make_public(RFC_GIX, RFC_GIY);
    assert_eq!(private.public.0, expected.0);
}

/// RFC 5903 §8.1: приватный ключ респондента даёт эталонный публичный ключ.
#[test]
fn rfc5903_responder_public_key() {
    let ecdh = Ecdh::p256();
    let private = make_private(&ecdh, RFC_R);
    let expected = make_public(RFC_GRX, RFC_GRY);
    assert_eq!(private.public.0, expected.0);
}

/// RFC 5903 §8.1: обе стороны получают эталонный общий секрет girx.
#[test]
fn rfc5903_shared_secret_both_directions() {
    let ecdh = Ecdh::p256();
    let alice = make_private(&ecdh, RFC_I);
    let bob = make_private(&ecdh, RFC_R);
    let expected = hex_bytes(RFC_GIRX);

    let alice_secret = ecdh.shared_secret(&alice, &bob.public).unwrap();
    let bob_secret = ecdh.shared_secret(&bob, &alice.public).unwrap();

    assert_eq!(alice_secret.as_slice(), expected.as_slice());
    assert_eq!(bob_secret.as_slice(), expected.as_slice());
}

/// Свежие ключи: секреты совпадают, публичный ключ на кривой, приватный в 1..n-1.
#[test]
fn generated_keypair_roundtrip() {
    let ecdh = Ecdh::p256();
    let alice = ecdh.generate_keypair().unwrap();
    let bob = ecdh.generate_keypair().unwrap();

    assert!(alice.secret >= BigUint::from(1u8) && alice.secret < ecdh.curve.n);
    assert!(ecdh.is_on_curve(&alice.public.0));
    assert!(ecdh.is_on_curve(&bob.public.0));

    let s1 = ecdh.shared_secret(&alice, &bob.public).unwrap();
    let s2 = ecdh.shared_secret(&bob, &alice.public).unwrap();
    assert_eq!(s1, s2);
}

/// serialize -> deserialize возвращает исходную точку, вывод ровно 65 байт.
#[test]
fn serialize_roundtrip() {
    let ecdh = Ecdh::p256();
    let key = ecdh.generate_keypair().unwrap();

    let bytes = ecdh.serialize_public(&key.public).unwrap();
    assert_eq!(bytes.len(), 65);
    assert_eq!(bytes[0], 0x04);

    let parsed = ecdh.deserialize_public(&bytes).unwrap();
    assert_eq!(parsed.0, key.public.0);
}

/// Left-pad координат: точка с короткой x-координатой сериализуется в 65 байт.
/// Используем эталонный публичный ключ инициатора — просто как валидную точку;
/// паддинг косвенно проверен roundtrip-тестом выше, тут проверяем явно на
/// точке G (x и y по 32 байта, граничный случай «без паддинга»).
#[test]
fn serialize_base_point() {
    let ecdh = Ecdh::p256();
    let g = EcdhPublicKey(EcPoint::Affine {
        x: ecdh.curve.gx.clone(),
        y: ecdh.curve.gy.clone(),
    });
    let bytes = ecdh.serialize_public(&g).unwrap();
    assert_eq!(bytes.len(), 65);
    assert_eq!(ecdh.deserialize_public(&bytes).unwrap().0, g.0);
}

/// Отказы десериализации: длина, префикс, точка не на кривой.
#[test]
fn deserialize_rejects_bad_input() {
    let ecdh = Ecdh::p256();

    // неверная длина
    assert!(ecdh.deserialize_public(&[0x04; 64]).is_err());
    assert!(ecdh.deserialize_public(&[0x04; 66]).is_err());

    // неверный префикс (compressed point нам не поддерживается)
    let mut bad_prefix = ecdh
        .serialize_public(&make_public(RFC_GIX, RFC_GIY))
        .unwrap();
    bad_prefix[0] = 0x02;
    assert!(ecdh.deserialize_public(&bad_prefix).is_err());

    // координаты с кривой подпорчены: (x, y+1)
    let bad_point = make_public(RFC_GIX, RFC_GIY);
    if let EcPoint::Affine { x, y } = bad_point.0.clone() {
        let tampered = EcdhPublicKey(EcPoint::Affine {
            x,
            y: y + BigUint::from(1u8),
        });
        let bytes = ecdh.serialize_public(&tampered).unwrap();
        assert!(matches!(
            ecdh.deserialize_public(&bytes),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
}

/// Сериализация бесконечности запрещена.
#[test]
fn serialize_infinity_fails() {
    let ecdh = Ecdh::p256();
    let inf = EcdhPublicKey(EcPoint::Infinity);
    assert!(matches!(
        ecdh.serialize_public(&inf),
        Err(CryptoError::Dh(_))
    ));
}

/// Общий секрет с точкой не на кривой отклоняется.
#[test]
fn shared_secret_rejects_off_curve_peer() {
    let ecdh = Ecdh::p256();
    let alice = ecdh.generate_keypair().unwrap();
    let fake = EcdhPublicKey(EcPoint::Affine {
        x: BigUint::from(1u8),
        y: BigUint::from(1u8),
    });
    assert_eq!(
        ecdh.shared_secret(&alice, &fake),
        Err(CryptoError::InvalidPublicKey)
    );
}

/// Общий секрет с бесконечностью отклоняется (is_on_curve(Infinity) == false).
#[test]
fn shared_secret_rejects_infinity() {
    let ecdh = Ecdh::p256();
    let alice = ecdh.generate_keypair().unwrap();
    let inf = EcdhPublicKey(EcPoint::Infinity);
    assert_eq!(
        ecdh.shared_secret(&alice, &inf),
        Err(CryptoError::InvalidPublicKey)
    );
}

/// n * G == Infinity — sanity-проверка порядка подгруппы.
#[test]
fn order_times_generator_is_infinity() {
    let ecdh = Ecdh::p256();
    let g = EcPoint::Affine {
        x: ecdh.curve.gx.clone(),
        y: ecdh.curve.gy.clone(),
    };
    let n = ecdh.curve.n.clone();
    assert_eq!(ecdh.scalar_mul(&n, &g), EcPoint::Infinity);
}

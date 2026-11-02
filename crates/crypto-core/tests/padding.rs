use crypto_core::padding::{
    ansix923::AnsiX923Padding, create_padding, iso10126::Iso10126Padding, pkcs7::Pkcs7Padding,
    zeros::ZerosPadding, Padding, PaddingKind,
};

#[test]
fn pkcs7_kind_roundtrip() {
    let p = create_padding(PaddingKind::Pkcs7);
    assert_eq!(p.kind(), PaddingKind::Pkcs7);
}

mod zeros {
    use super::*;

    const BS: usize = 16;

    #[test]
    fn pad_len_basic() {
        let z = ZerosPadding;
        assert_eq!(z.pad_len(5, BS), 11);
        assert_eq!(z.pad_len(15, BS), 1);
        assert_eq!(z.pad_len(0, BS), BS);
        assert_eq!(z.pad_len(16, BS), BS);
    }

    #[test]
    fn pad_len_relationship() {
        let z = ZerosPadding;
        for len in 0..100 {
            assert_eq!((len + z.pad_len(len, BS)) % BS, 0);
        }
    }

    #[test]
    fn apply_fills_tail() {
        let z = ZerosPadding;
        let mut block = [0xAAu8; BS];
        z.apply(&mut block, 10).unwrap();

        assert_eq!(&block[..10], &[0xAA; 10]);
        assert_eq!(&block[10..], &[0x00; 6]);
    }

    #[test]
    fn apply_full_block() {
        let z = ZerosPadding;
        let mut block = [0xAAu8; BS];
        z.apply(&mut block, BS).unwrap();
        assert_eq!(block, [0xAA; BS]);
    }

    #[test]
    fn apply_data_len_too_big() {
        let z = ZerosPadding;
        let mut block = [0u8; BS];
        assert!(z.apply(&mut block, BS + 1).is_err());
    }

    #[test]
    fn roundtrip_simple() {
        let z = ZerosPadding;
        let data = b"hello world";
        let mut block = [0u8; BS];

        block[..data.len()].copy_from_slice(data);
        z.apply(&mut block, data.len()).unwrap();

        let real_len = z.unpad(&block).unwrap();
        assert_eq!(real_len, data.len());
        assert_eq!(&block[..real_len], data);
    }

    #[test]
    fn roundtrip_exact_block() {
        let z = ZerosPadding;
        let data = [0xBBu8; BS];
        let pad = z.pad_len(BS, BS);
        let mut buf = vec![0u8; BS + pad];
        buf[..BS].copy_from_slice(&data);
        z.apply(&mut buf, BS).unwrap();

        assert_eq!(z.unpad(&buf[BS..]).unwrap(), 0);
        assert_eq!(&buf[..BS], &data);
    }

    #[test]
    fn unpad_no_trailing_zeros() {
        let z = ZerosPadding;
        let block = [0xFFu8; BS];
        assert_eq!(z.unpad(&block).unwrap(), BS);
    }

    #[test]
    fn unpad_all_zeros() {
        let z = ZerosPadding;
        let block = [0u8; BS];
        assert_eq!(z.unpad(&block).unwrap(), 0);
    }

    #[test]
    fn unpad_empty_block() {
        let z = ZerosPadding;
        assert!(z.unpad(&[]).is_err());
    }

    #[test]
    fn unpad_mixed() {
        let z = ZerosPadding;
        let mut block = [0u8; BS];
        block[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(z.unpad(&block).unwrap(), 3);
    }
}

mod pkcs7 {
    use super::*;

    const BS: usize = 16;

    #[test]
    fn pad_len_basic() {
        let p = Pkcs7Padding;
        assert_eq!(p.pad_len(0, BS), BS);
        assert_eq!(p.pad_len(5, BS), 11);
        assert_eq!(p.pad_len(15, BS), 1);
        assert_eq!(p.pad_len(16, BS), BS);
    }

    #[test]
    fn pad_len_relationship() {
        let p = Pkcs7Padding;
        for len in 0..100 {
            let pl = p.pad_len(len, BS);
            assert_eq!((len + pl) % BS, 0);
            assert!(pl >= 1 && pl <= BS);
        }
    }

    #[test]
    fn apply_fills_tail_with_pad_len() {
        let p = Pkcs7Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 10).unwrap();

        assert_eq!(&block[..10], &[0xAA; 10]);
        assert_eq!(&block[10..], &[6u8; 6]);
    }

    #[test]
    fn apply_full_padding_block() {
        let p = Pkcs7Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 0).unwrap();

        assert_eq!(block, [BS as u8; BS]);
    }

    #[test]
    fn apply_minimal_padding() {
        let p = Pkcs7Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, BS - 1).unwrap();

        assert_eq!(&block[..BS - 1], &[0xAA; BS - 1]);
        assert_eq!(block[BS - 1], 1);
    }

    #[test]
    fn apply_data_len_too_big() {
        let p = Pkcs7Padding;
        let mut block = [0u8; BS];
        assert!(p.apply(&mut block, BS + 1).is_err());
    }

    #[test]
    fn roundtrip_simple() {
        let p = Pkcs7Padding;
        let data = b"hello world";
        let mut block = [0u8; BS];

        block[..data.len()].copy_from_slice(data);
        p.apply(&mut block, data.len()).unwrap();

        assert_eq!(p.unpad(&block).unwrap(), data.len());
        assert_eq!(&block[..data.len()], data);
    }

    #[test]
    fn roundtrip_exact_block() {
        let p = Pkcs7Padding;
        let data = [0xBBu8; BS];
        let pad = p.pad_len(BS, BS);
        assert_eq!(pad, BS);

        let mut buf = vec![0u8; BS + pad];
        buf[..BS].copy_from_slice(&data);
        p.apply(&mut buf[BS..], 0).unwrap();

        assert_eq!(buf[BS..], [BS as u8; BS]);
        assert_eq!(p.unpad(&buf[BS..]).unwrap(), 0);
        assert_eq!(&buf[..BS], &data);
    }

    #[test]
    fn roundtrip_various_lengths() {
        let p = Pkcs7Padding;
        for len in 0..64 {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let total = len + p.pad_len(len, BS);
            let mut buf = vec![0u8; total];
            buf[..len].copy_from_slice(&data);
            p.apply(&mut buf[len..], 0).unwrap();

            assert_eq!(p.unpad(&buf[len..]).unwrap(), 0, "failed at len={}", len);
            assert_eq!(&buf[..len], &data);
        }
    }

    #[test]
    fn unpad_empty_block() {
        let p = Pkcs7Padding;
        assert!(p.unpad(&[]).is_err());
    }

    #[test]
    fn unpad_corrupt_length_byte() {
        let p = Pkcs7Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[BS - 1] = (BS + 1) as u8;
        assert!(p.unpad(&block).is_err());

        block[BS - 1] = 0;
        assert!(p.unpad(&block).is_err());
    }

    #[test]
    fn unpad_garbage_in_padding() {
        let p = Pkcs7Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[12] = 0x05;
        assert!(p.unpad(&block).is_err());

        block[12] = 0x06;
        block[10] = 0x00;
        assert!(p.unpad(&block).is_err());
    }

    #[test]
    fn unpad_data_ending_with_pad_like_byte() {
        let p = Pkcs7Padding;
        let mut block = [0u8; BS];
        block[..10].copy_from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 6]);
        p.apply(&mut block, 10).unwrap();

        assert_eq!(p.unpad(&block).unwrap(), 10);
    }
}

mod ansix923 {
    use super::*;

    const BS: usize = 16;

    #[test]
    fn pad_len_basic() {
        let p = AnsiX923Padding;
        assert_eq!(p.pad_len(0, BS), BS);
        assert_eq!(p.pad_len(5, BS), 11);
        assert_eq!(p.pad_len(15, BS), 1);
        assert_eq!(p.pad_len(16, BS), BS);
    }

    #[test]
    fn pad_len_relationship() {
        let p = AnsiX923Padding;
        for len in 0..100 {
            assert_eq!((len + p.pad_len(len, BS)) % BS, 0);
            assert!(p.pad_len(len, BS) >= 1 && p.pad_len(len, BS) <= BS);
        }
    }

    #[test]
    fn apply_fills_tail() {
        let p = AnsiX923Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 10).unwrap();

        assert_eq!(&block[..10], &[0xAA; 10]);
        assert_eq!(&block[10..15], &[0x00; 5]);
        assert_eq!(block[15], 6);
    }

    #[test]
    fn apply_full_padding_block() {
        let p = AnsiX923Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 0).unwrap();

        assert_eq!(&block[..BS - 1], &[0x00; BS - 1]);
        assert_eq!(block[BS - 1], BS as u8);
    }

    #[test]
    fn apply_minimal_padding() {
        let p = AnsiX923Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, BS - 1).unwrap();

        assert_eq!(&block[..BS - 1], &[0xAA; BS - 1]);
        assert_eq!(block[BS - 1], 1);
    }

    #[test]
    fn apply_data_len_too_big() {
        let p = AnsiX923Padding;
        let mut block = [0u8; BS];
        assert!(p.apply(&mut block, BS + 1).is_err());
    }

    #[test]
    fn roundtrip_simple() {
        let p = AnsiX923Padding;
        let data = b"hello world";
        let mut block = [0u8; BS];

        block[..data.len()].copy_from_slice(data);
        p.apply(&mut block, data.len()).unwrap();

        assert_eq!(p.unpad(&block).unwrap(), data.len());
        assert_eq!(&block[..data.len()], data);
    }

    #[test]
    fn roundtrip_exact_block() {
        let p = AnsiX923Padding;
        let data = [0xBBu8; BS];
        let pad = p.pad_len(BS, BS);
        assert_eq!(pad, BS);

        let mut buf = vec![0u8; BS + pad];
        buf[..BS].copy_from_slice(&data);
        p.apply(&mut buf[BS..], 0).unwrap();

        assert_eq!(p.unpad(&buf[BS..]).unwrap(), 0);
        assert_eq!(&buf[..BS], &data);
    }

    #[test]
    fn roundtrip_various_lengths() {
        let p = AnsiX923Padding;
        for len in 0..64 {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let total = len + p.pad_len(len, BS);
            let mut buf = vec![0u8; total];
            buf[..len].copy_from_slice(&data);
            p.apply(&mut buf[len..], 0).unwrap();

            assert_eq!(p.unpad(&buf[len..]).unwrap(), 0, "failed at len={}", len);
            assert_eq!(&buf[..len], &data);
        }
    }

    #[test]
    fn unpad_empty_block() {
        let p = AnsiX923Padding;
        assert!(p.unpad(&[]).is_err());
    }

    #[test]
    fn unpad_corrupt_length_byte() {
        let p = AnsiX923Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[BS - 1] = (BS + 1) as u8;
        assert!(p.unpad(&block).is_err());

        block[BS - 1] = 0;
        assert!(p.unpad(&block).is_err());
    }

    #[test]
    fn unpad_garbage_in_padding_body() {
        let p = AnsiX923Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[12] = 0xFF;
        assert!(p.unpad(&block).is_err());
    }

    #[test]
    fn unpad_valid_last_byte_is_data() {
        let p = AnsiX923Padding;
        let mut block = [0u8; BS];
        block[..15].copy_from_slice(&[0x11u8; 15]);
        assert!(p.unpad(&block).is_err());
    }
}

mod iso10126 {
    use super::*;

    const BS: usize = 16;

    #[test]
    fn pad_len_basic() {
        let p = Iso10126Padding;
        assert_eq!(p.pad_len(0, BS), BS);
        assert_eq!(p.pad_len(5, BS), 11);
        assert_eq!(p.pad_len(15, BS), 1);
        assert_eq!(p.pad_len(16, BS), BS);
    }

    #[test]
    fn pad_len_relationship() {
        let p = Iso10126Padding;
        for len in 0..100 {
            let pl = p.pad_len(len, BS);
            assert_eq!((len + pl) % BS, 0);
            assert!(pl >= 1 && pl <= BS);
        }
    }

    #[test]
    fn apply_last_byte_is_len() {
        let p = Iso10126Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 10).unwrap();

        assert_eq!(&block[..10], &[0xAA; 10]);
        assert_eq!(block[BS - 1], 6);
    }

    #[test]
    fn apply_full_padding_block() {
        let p = Iso10126Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, 0).unwrap();
        assert_eq!(block[BS - 1], BS as u8);
    }

    #[test]
    fn apply_minimal_padding() {
        let p = Iso10126Padding;
        let mut block = [0xAAu8; BS];
        p.apply(&mut block, BS - 1).unwrap();
        assert_eq!(block[BS - 1], 1);
    }

    #[test]
    fn apply_padding_body_is_random() {
        let p = Iso10126Padding;
        let mut b1 = [0u8; BS];
        let mut b2 = [0u8; BS];
        p.apply(&mut b1, 5).unwrap();
        p.apply(&mut b2, 5).unwrap();

        assert_eq!(b1[BS - 1], b2[BS - 1]);
        assert_ne!(&b1[5..BS - 1], &b2[5..BS - 1]);
    }

    #[test]
    fn apply_data_len_too_big() {
        let p = Iso10126Padding;
        let mut block = [0u8; BS];
        assert!(p.apply(&mut block, BS + 1).is_err());
    }

    #[test]
    fn roundtrip_simple() {
        let p = Iso10126Padding;
        let data = b"hello world";
        let mut block = [0u8; BS];

        block[..data.len()].copy_from_slice(data);
        p.apply(&mut block, data.len()).unwrap();

        assert_eq!(p.unpad(&block).unwrap(), data.len());
        assert_eq!(&block[..data.len()], data);
    }

    #[test]
    fn roundtrip_exact_block() {
        let p = Iso10126Padding;
        let data = [0xBBu8; BS];
        let pad = p.pad_len(BS, BS);
        let mut buf = vec![0u8; BS + pad];
        buf[..BS].copy_from_slice(&data);
        p.apply(&mut buf[BS..], 0).unwrap();

        assert_eq!(p.unpad(&buf[BS..]).unwrap(), 0);
        assert_eq!(&buf[..BS], &data);
    }

    #[test]
    fn roundtrip_various_lengths() {
        let p = Iso10126Padding;
        for len in 0..64 {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let total = len + p.pad_len(len, BS);
            let mut buf = vec![0u8; total];
            buf[..len].copy_from_slice(&data);
            p.apply(&mut buf[len..], 0).unwrap();

            assert_eq!(p.unpad(&buf[len..]).unwrap(), 0, "failed at len={}", len);
            assert_eq!(&buf[..len], &data);
        }
    }

    #[test]
    fn unpad_empty_block() {
        let p = Iso10126Padding;
        assert!(p.unpad(&[]).is_err());
    }

    #[test]
    fn unpad_corrupt_length_byte() {
        let p = Iso10126Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[BS - 1] = (BS + 1) as u8;
        assert!(p.unpad(&block).is_err());

        block[BS - 1] = 0;
        assert!(p.unpad(&block).is_err());
    }

    #[test]
    fn unpad_ignores_padding_body() {
        let p = Iso10126Padding;
        let mut block = [0u8; BS];
        p.apply(&mut block, 10).unwrap();

        block[12] = 0xFF;
        assert_eq!(p.unpad(&block).unwrap(), 10);

        block[10] = 0x01;
        assert_eq!(p.unpad(&block).unwrap(), 10);
    }

    #[test]
    fn unpad_length_byte_less_than_block() {
        let p = Iso10126Padding;
        let mut block = [0xCCu8; BS];
        block[BS - 1] = 3;
        assert_eq!(p.unpad(&block).unwrap(), BS - 3);
    }
}

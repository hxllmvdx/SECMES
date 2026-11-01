use crypto_core::mode::{create_mode, ModeKind};

#[test]
fn mode_factory_works() {
    for k in [ModeKind::Ecb, ModeKind::Cbc, ModeKind::Ctr] {
        let _m = create_mode(k);
        assert_eq!(_m.kind(), k);
    }
}

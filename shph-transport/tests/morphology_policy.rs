use shph_obfuscation::ProfileTier;
use shph_transport::phantom_one::{
    PhantomOneConfig, PhantomOneEncoder, PhantomOneFrameType, SizeSelection,
};

#[test]
fn weighted_selection_is_reproducible_and_respects_eligible_weights() {
    let config = PhantomOneConfig::for_profile(ProfileTier::Medium)
        .with_selection(SizeSelection::Weighted([1, 3, 0, 0, 0, 0, 0]))
        .unwrap();
    let mut a = PhantomOneEncoder::from_seed_with_config(1, 42, config).unwrap();
    let mut b = PhantomOneEncoder::from_seed_with_config(1, 42, config).unwrap();
    let mut small = 0;
    for _ in 0..10_000 {
        let target = a.target_size(32, 1360).unwrap();
        assert_eq!(target, b.target_size(32, 1360).unwrap());
        assert!(matches!(target, 128 | 256));
        small += usize::from(target == 128);
    }
    assert!((2300..2700).contains(&small), "sample count {small}");
    assert_eq!(a.target_size(200, 1360).unwrap(), 256);
    assert!(a.target_size(300, 1360).is_err());
}

#[test]
fn padding_budget_applies_to_explicit_and_selected_targets() {
    let config = PhantomOneConfig::for_profile(ProfileTier::Medium).with_padding_budget(80);
    let mut encoder = PhantomOneEncoder::from_seed_with_config(1, 7, config).unwrap();
    // 128 - 24 - 64 = 40 tail bytes per frame.
    for _ in 0..2 {
        assert_eq!(
            encoder
                .encode(PhantomOneFrameType::Data, &[1; 64], 1360)
                .unwrap()
                .len(),
            128
        );
    }
    let before = encoder.metrics();
    assert!(encoder
        .encode(PhantomOneFrameType::Data, &[1; 64], 1360)
        .is_err());
    assert!(encoder
        .encode_with_target(PhantomOneFrameType::Data, &[1; 64], 128, 1360)
        .is_err());
    assert_eq!(encoder.metrics(), before);
    assert_eq!(before.padding_bytes, 80);
    assert_eq!(before.header_bytes, 48);
    assert_eq!(encoder.next_sequence(), Some(2));
    // No padding is still allowed, without leaving canonical classes.
    assert!(encoder
        .encode(PhantomOneFrameType::Data, &[1; 104], 1360)
        .is_ok());
}

#[test]
fn invalid_selection_does_not_consume_rng_or_sequence() {
    let config = PhantomOneConfig::for_profile(ProfileTier::Low)
        .with_selection(SizeSelection::Weighted([1, 1, 0, 0, 0, 0, 0]))
        .unwrap();
    let mut a = PhantomOneEncoder::from_seed_with_config(1, 42, config).unwrap();
    let mut b = PhantomOneEncoder::from_seed_with_config(1, 42, config).unwrap();
    assert!(a.target_size(4096, 1360).is_err());
    assert_eq!(
        a.target_size(32, 1360).unwrap(),
        b.target_size(32, 1360).unwrap()
    );
    assert_eq!(a.next_sequence(), Some(0));
    assert!(config
        .with_selection(SizeSelection::Weighted([0; 7]))
        .is_err());
    assert!(config
        .with_selection(SizeSelection::Weighted([1; 7]))
        .is_err());
}

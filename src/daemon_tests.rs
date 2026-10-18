use super::*;

#[test]
fn never_policy_never_needs_pin() {
    assert!(!needs_pin(Some(PinPolicy::Never), false));
    assert!(!needs_pin(Some(PinPolicy::Never), true));
}

#[test]
fn always_policy_needs_pin_even_after_verification() {
    assert!(needs_pin(Some(PinPolicy::Always), true));
}

#[test]
fn once_policy_needs_pin_until_verified() {
    assert!(needs_pin(Some(PinPolicy::Once), false));
    assert!(!needs_pin(Some(PinPolicy::Once), true));
}

#[test]
fn unknown_policy_always_needs_pin() {
    assert!(needs_pin(None, false));
    assert!(needs_pin(None, true));
}

#[test]
fn default_policy_is_always_for_signature_slot() {
    assert_eq!(
        slot_pin_policy(SlotId::Signature, PinPolicy::Default),
        PinPolicy::Always
    );
}

#[test]
fn default_policy_is_once_for_other_key_slots() {
    for slot in [
        SlotId::Authentication,
        SlotId::KeyManagement,
        SlotId::Retired(RetiredSlotId::R1),
    ] {
        assert_eq!(slot_pin_policy(slot, PinPolicy::Default), PinPolicy::Once);
    }
}

#[test]
fn default_policy_stays_unresolved_for_card_authentication_slot() {
    assert_eq!(
        slot_pin_policy(SlotId::CardAuthentication, PinPolicy::Default),
        PinPolicy::Default
    );
}

#[test]
fn explicit_policy_is_unchanged() {
    assert_eq!(
        slot_pin_policy(SlotId::Signature, PinPolicy::Never),
        PinPolicy::Never
    );
}

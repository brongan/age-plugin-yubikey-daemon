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

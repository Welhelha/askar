// Change the comments to english
//! Verifies that unknown JWK members are ignored (RFC 7517 §4).
//! This test fails until the `_ => ()` arm of `JwkMapVisitor` is fixed.

use askar_crypto::{
    alg::{AnyKey, AnyKeyCreate, KeyAlg},
    jwk::{FromJwk, JwkParts, ToJwk},
};

/// Builds a valid ML-DSA public JWK, then injects an additional member.
fn jwk_with_extra(alg: KeyAlg, extra: &str) -> (Box<AnyKey>, String) {
    let key = Box::<AnyKey>::random_det(alg, b"unknown-members-test").unwrap();
    let public = key.to_jwk_public(None).unwrap();
    let parts = JwkParts::try_from_str(&public).unwrap();

    let jwk = format!(
        r#"{{"kty":"AKP","alg":"{}","pub":"{}",{}}}"#,
        parts.alg.as_ref(),
        parts.pub_key.as_ref(),
        extra
    );
    (key, jwk)
}

#[test]
fn unknown_string_member_is_ignored() {
    for alg in [KeyAlg::MlDsa44, KeyAlg::MlDsa65, KeyAlg::MlDsa87] {
        let (key, jwk) = jwk_with_extra(alg, r#""unknown":"x""#);
        let imported = Box::<AnyKey>::from_jwk(&jwk).expect("unknown string member rejected");
        assert_eq!(
            key.to_jwk_thumbprint(None).unwrap(),
            imported.to_jwk_thumbprint(None).unwrap()
        );
    }
}

#[test]
fn unknown_bool_member_is_ignored() {
    let (key, jwk) = jwk_with_extra(KeyAlg::MlDsa44, r#""unknown":true"#);
    let imported = Box::<AnyKey>::from_jwk(&jwk).expect("unknown bool member rejected");
    assert_eq!(
        key.to_jwk_thumbprint(None).unwrap(),
        imported.to_jwk_thumbprint(None).unwrap()
    );
}

#[test]
fn unknown_number_and_null_members_are_ignored() {
    for extra in [r#""unknown":42"#, r#""unknown":null"#] {
        let (key, jwk) = jwk_with_extra(KeyAlg::MlDsa44, extra);
        let imported = Box::<AnyKey>::from_jwk(&jwk)
            .unwrap_or_else(|e| panic!("rejected {extra}: {e:?}"));
        assert_eq!(
            key.to_jwk_thumbprint(None).unwrap(),
            imported.to_jwk_thumbprint(None).unwrap()
        );
    }
}

#[test]
fn unknown_member_before_known_members_is_ignored() {
    let key = Box::<AnyKey>::random_det(KeyAlg::MlDsa44, b"order-test").unwrap();
    let public = key.to_jwk_public(None).unwrap();
    let p = JwkParts::try_from_str(&public).unwrap();
    let jwk = format!(
        r#"{{"unknown":"x","pub":"{}","alg":"{}","kty":"AKP"}}"#,
        p.pub_key.as_ref(),
        p.alg.as_ref()
    );
    let imported = Box::<AnyKey>::from_jwk(&jwk).expect("leading unknown member rejected");
    assert_eq!(
        key.to_jwk_thumbprint(None).unwrap(),
        imported.to_jwk_thumbprint(None).unwrap()
    );
}

#[test]
fn several_unknown_members_are_ignored() {
    let (key, jwk) = jwk_with_extra(KeyAlg::MlDsa44, r#""a":"1","b":true,"c":7"#);
    let imported = Box::<AnyKey>::from_jwk(&jwk).expect("multiple unknown members rejected");
    assert_eq!(
        key.to_jwk_thumbprint(None).unwrap(),
        imported.to_jwk_thumbprint(None).unwrap()
    );
}

/// Nested values : to keep separate, as the support by `serde_json_core`
/// with `IgnoredAny` is not guaranteed. A failure here does not invalidate the fix
/// for the simple values, but merits being mentioned in the issue.
#[test]
fn unknown_nested_members_are_ignored() {
    for extra in [r#""unknown":[1,2,3]"#, r#""unknown":{"a":"b"}"#] {
        let (key, jwk) = jwk_with_extra(KeyAlg::MlDsa44, extra);
        let imported = Box::<AnyKey>::from_jwk(&jwk)
            .unwrap_or_else(|e| panic!("rejected {extra}: {e:?}"));
        assert_eq!(
            key.to_jwk_thumbprint(None).unwrap(),
            imported.to_jwk_thumbprint(None).unwrap()
        );
    }
}

/// Guard : an invalid JWK must always be rejected, even with an unknown member.
#[test]
fn unknown_member_does_not_mask_real_errors() {
    let jwk = r#"{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA","unknown":"x"}"#;
    assert!(Box::<AnyKey>::from_jwk(jwk).is_err());
}
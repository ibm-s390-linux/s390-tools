// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use pv::request::CertVerifier;
use pv::test_utils::*;
use pv::{Error, HkdVerifyErrorType::*};
use std::ffi::c_int;

#[track_caller]
fn verify_sign_error(exp_raw: c_int, obs: Error) {
    verify_sign_error_slice(&[exp_raw], obs)
}
fn verify_sign_error_slice(exp_raw: &[c_int], obs: Error) {
    if exp_raw
        .iter()
        .filter(|e| match &obs {
            Error::HkdVerify(ty) => match ty {
                IbmSignInvalid(err, _d) => &&err.as_raw() == e,
                _ => false,
            },
            e => panic!("Unexpected error type: {e:?}"),
        })
        .count()
        == 0
    {
        panic!("Error {obs:?} did not match one of the expected {exp_raw:?}");
    }
}

#[test]
fn verifier_new() {
    let root_chn_crt = get_cert_asset_path_string("root_ca.chained.crt");
    let root_crt = get_cert_asset_path_string("root_ca.crt");
    let inter_crt = get_cert_asset_path_string("inter_ca.crt");
    let inter_fake_crt = get_cert_asset_path_string("fake_inter_ca.crt");
    let inter_fake_crl = get_cert_asset_path_string("fake_inter_ca.crl");
    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let ibm_crt = get_cert_asset_path_string("ibm.crt");
    let ibm_early_crt = get_cert_asset_path_string("ibm_outdated_early.crl");
    let ibm_late_crt = get_cert_asset_path_string("ibm_outdated_late.crl");
    let ibm_rev_crt = get_cert_asset_path_string("ibm_rev.crt");

    // Too many signing keys
    let verifier = CertVerifier::new(&[ibm_crt.clone(), ibm_rev_crt.clone()], &[], &None, true);
    assert!(matches!(verifier, Err(Error::HkdVerify(ManyIbmSignKeys))));

    // No CRL for each X509
    let verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_crt.clone()],
        &[inter_crl.clone()],
        &Some(root_crt),
        false,
    );
    verify_sign_error(3, verifier.unwrap_err());
    let verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_crt.clone()],
        &[],
        &Some(root_chn_crt.clone()),
        false,
    );
    verify_sign_error(3, verifier.unwrap_err());

    // Wrong intermediate (or ibm key)
    let verifier = CertVerifier::new(
        &[inter_fake_crt, ibm_crt.clone()],
        &[inter_fake_crl],
        &Some(root_chn_crt.clone()),
        true,
    );
    // Depending on the OpenSSL version different error codes can appear
    verify_sign_error_slice(&[20, 30], verifier.unwrap_err());

    // Wrong root ca
    let verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_crt.clone()],
        &[inter_crl.clone()],
        &None,
        true,
    );
    verify_sign_error(20, verifier.unwrap_err());

    // Correct signing key + intermediate cert
    let _verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_crt.clone()],
        &[inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    )
    .unwrap();

    // No intermediate key
    let verifier = CertVerifier::new(&[ibm_crt], &[], &Some(root_chn_crt.clone()), false);
    verify_sign_error(20, verifier.unwrap_err());

    // IBM Sign outdated
    let verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_early_crt],
        &[inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    );
    assert!(matches!(verifier, Err(Error::HkdVerify(NoIbmSignKey))));
    let verifier = CertVerifier::new(
        &[inter_crt.clone(), ibm_late_crt],
        &[inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    );
    assert!(matches!(verifier, Err(Error::HkdVerify(NoIbmSignKey))));

    // Revoked
    let verifier = CertVerifier::new(
        &[inter_crt, ibm_rev_crt],
        &[inter_crl],
        &Some(root_chn_crt),
        false,
    );
    verify_sign_error(23, verifier.unwrap_err());
}

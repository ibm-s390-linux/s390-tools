// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(test)]

use super::{helper, helper::*, *};
use crate::{Error, HkdVerifyErrorType::*};
use core::slice;
use openssl::stack::Stack;

use crate::test_utils::*;

pub fn mock_endpt(res: &str) -> mockito::Mock {
    let res_path = get_cert_asset_path(res);

    mockito::mock("GET", format!("/crl/{res}").as_str())
        .with_header("content-type", "application/pkix-crl")
        .with_body_from_file(res_path)
        .create()
}

#[track_caller]
fn verify_sign_error(exp_raw: libc::c_int, obs: Error) {
    verify_sign_error_slice(&[exp_raw], obs)
}
fn verify_sign_error_slice(exp_raw: &[libc::c_int], obs: Error) {
    if exp_raw
        .into_iter()
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
impl std::fmt::Debug for CertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertVerifier")
    }
}

#[test]
fn store_setup() {
    let ibm_str = get_cert_asset_path_string("ibm.crt");
    let inter_str = get_cert_asset_path_string("inter.crt");

    let store = helper::store_setup(&None, &vec![], &vec![ibm_str, inter_str]);
    assert!(store.is_ok());
}

#[test]
fn verify_chain_online() {
    let ibm_crt = load_gen_cert("ibm.crt");
    let inter_crt = load_gen_cert("inter_ca.crt");
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");

    let mock_inter = mock_endpt("inter_ca.crl");

    let mut store = helper::store_setup(&Some(root_crt), &vec![], &vec![]).unwrap();
    download_crls_into_store(&mut store, slice::from_ref(&ibm_crt)).unwrap();
    let store = store.build();

    mock_inter.assert();

    let mut sk = Stack::<X509>::new().unwrap();
    sk.push(inter_crt).unwrap();
    verify_chain(&store, &sk, &vec![ibm_crt.clone()]).unwrap();
    assert!(verify_chain(&store, &sk, &vec!(ibm_crt)).is_ok());
}

#[test]
fn verify_chain_offline() {
    let ibm_crt = load_gen_cert("ibm.crt");
    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let inter_crt = load_gen_cert("inter_ca.crt");
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");

    let store = helper::store_setup(&Some(root_crt), &vec![inter_crl], &vec![])
        .unwrap()
        .build();

    let mut sk = Stack::<X509>::new().unwrap();
    sk.push(inter_crt).unwrap();
    assert!(verify_chain(&store, &sk, &vec![ibm_crt]).is_ok());
}

#[test]
fn verify_online() {
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");
    let inter_crt = get_cert_asset_path_string("inter_ca.crt");
    let ibm_crt = get_cert_asset_path_string("ibm.crt");
    let hkd_revoked = load_gen_cert("host_rev.crt");
    let hkd_inv = load_gen_cert("host_invalid_signing_key.crt");
    let hkd_exp = load_gen_cert("host_crt_expired.crt");
    let hkd = load_gen_cert("host.crt");

    let mock_inter = mock_endpt("inter_ca.crl");
    let mock_ibm = mock_endpt("ibm.crl");

    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let ibm_crl = get_cert_asset_path_string("ibm.crl");
    let verifier = CertVerifier::new(
        &vec![ibm_crt, inter_crt],
        &vec![ibm_crl, inter_crl],
        &Some(root_crt),
        false,
    )
    .unwrap();

    mock_inter.assert();

    verifier.verify(&hkd).unwrap();

    mock_ibm.assert();
    assert!(matches!(
        verifier.verify(&hkd_revoked),
        Err(Error::HkdVerify(HdkRevoked))
    ));

    assert!(matches!(
        verifier.verify(&hkd_inv),
        Err(Error::HkdVerify(IssuerMismatch))
    ));

    assert!(matches!(
        verifier.verify(&hkd_exp),
        Err(Error::HkdVerify(AfterValidity))
    ));
}

#[test]
fn verify_offline() {
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");
    let inter_crt = get_cert_asset_path_string("inter_ca.crt");
    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let ibm_crt = get_cert_asset_path_string("ibm.crt");
    let ibm_crl = get_cert_asset_path_string("ibm.crl");
    let hkd_revoked = load_gen_cert("host_rev.crt");
    let hkd_inv = load_gen_cert("host_invalid_signing_key.crt");
    let hkd_exp = load_gen_cert("host_crt_expired.crt");
    let hkd = load_gen_cert("host.crt");

    let verifier = CertVerifier::new(
        &vec![ibm_crt, inter_crt],
        &vec![ibm_crl, inter_crl],
        &Some(root_crt),
        true,
    )
    .unwrap();

    verifier.verify(&hkd).unwrap();
    assert!(matches!(
        verifier.verify(&hkd_revoked),
        Err(Error::HkdVerify(HdkRevoked))
    ));

    assert!(matches!(
        verifier.verify(&hkd_inv),
        Err(Error::HkdVerify(IssuerMismatch))
    ));

    assert!(matches!(
        verifier.verify(&hkd_exp),
        Err(Error::HkdVerify(AfterValidity))
    ));
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

    // To many signing keys
    let verifier = CertVerifier::new(
        &vec![ibm_crt.clone(), ibm_rev_crt.clone()],
        &vec![],
        &None,
        true,
    );
    assert!(matches!(verifier, Err(Error::HkdVerify(ManyIbmSignKeys))));

    // no CRL for each X509
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_crt.clone()],
        &vec![inter_crl.clone()],
        &Some(root_crt.clone()),
        false,
    );
    verify_sign_error(3, verifier.unwrap_err());
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_crt.clone()],
        &vec![],
        &Some(root_chn_crt.clone()),
        false,
    );
    verify_sign_error(3, verifier.unwrap_err());

    // wrong intermediate (or ibm key)
    let verifier = CertVerifier::new(
        &vec![inter_fake_crt, ibm_crt.clone()],
        &vec![inter_fake_crl],
        &Some(root_chn_crt.clone()),
        true,
    );
    //Depending on the OpenSSL version different error codes can appear
    verify_sign_error_slice(&[20, 30], verifier.unwrap_err());

    //wrong root ca
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_crt.clone()],
        &vec![inter_crl.clone()],
        &None,
        true,
    );
    verify_sign_error(20, verifier.unwrap_err());

    //correct signing key + intermediate cert
    let _verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_crt.clone()],
        &vec![inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    )
    .unwrap();

    // no intermediate key
    let verifier = CertVerifier::new(
        &vec![ibm_crt.clone()],
        &vec![],
        &Some(root_chn_crt.clone()),
        false,
    );
    verify_sign_error(20, verifier.unwrap_err());

    //Ibm Sign outdated
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_early_crt.clone()],
        &vec![inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    );
    assert!(matches!(verifier, Err(Error::HkdVerify(NoIbmSignKey))));
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_late_crt.clone()],
        &vec![inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    );
    assert!(matches!(verifier, Err(Error::HkdVerify(NoIbmSignKey))));

    // revoked
    let verifier = CertVerifier::new(
        &vec![inter_crt.clone(), ibm_rev_crt.clone()],
        &vec![inter_crl.clone()],
        &Some(root_chn_crt.clone()),
        false,
    );
    verify_sign_error(23, verifier.unwrap_err());
}

#[test]
fn dist_points() {
    let crt = load_gen_cert("ibm.crt");
    let res = x509_dist_points(&crt);
    let exp = vec!["http://127.0.0.1:1234/crl/inter_ca.crl"];
    assert_eq!(res, exp);
}

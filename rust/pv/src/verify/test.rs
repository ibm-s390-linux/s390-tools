// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(test)]

use super::{helper, helper::*, *};
use crate::{misc::read_crls, Error, HkdVerifyErrorType::*};
use openssl::{stack::Stack, x509::X509Crl};
use std::path::Path;

use crate::test_utils::*;

//mock function
pub fn download_first_crl_from_x509(cert: &X509Ref) -> Result<Option<Vec<X509Crl>>> {
    fn mock_download<P: AsRef<Path>>(path: P) -> Result<Vec<X509Crl>> {
        read_crls(&std::fs::read(path)?)
    }

    for dist_point in x509_dist_points(cert) {
        {
            let path = get_cert_asset_path(&dist_point);
            let crls = if let Ok(buf) = mock_download(&path) {
                buf
            } else {
                continue;
            };
            return Ok(Some(crls));
        }
    }
    Ok(None)
}

#[test]
fn store_setup() {
    let ibm_str = get_cert_asset_path_string("ibm.crt");
    let inter_str = get_cert_asset_path_string("inter.crt");

    let store = helper::store_setup(&None, &[], &[ibm_str, inter_str]);
    assert!(store.is_ok());
}

#[test]
fn verify_chain_online() {
    let ibm_crt = get_cert_asset_path_string("ibm.crt");
    let inter_crt = get_cert_asset_path_string("inter_ca.crt");
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");

    let ret = CertVerifier::new(&[ibm_crt, inter_crt], &[], &root_crt.into(), false);
    assert!(ret.is_ok(), "CertVerifier::new failed: {ret:?}");
}

#[test]
fn verify_chain_offline() {
    let ibm_crt = load_gen_cert("ibm.crt");
    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let inter_crt = load_gen_cert("inter_ca.crt");
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");

    let store = helper::store_setup(&Some(root_crt), &[inter_crl], &[])
        .unwrap()
        .build();

    let mut sk = Stack::<X509>::new().unwrap();
    sk.push(inter_crt).unwrap();
    assert!(verify_chain(&store, &sk, &[ibm_crt]).is_ok());
}

#[test]
fn dist_points() {
    let crt = load_gen_cert("ibm.crt");
    let res = x509_dist_points(&crt);
    let exp = vec!["inter_ca.crl"];
    assert_eq!(res, exp);
}

fn verify(offline: bool, ibm_crt: &'static str, ibm_crl: &'static str) {
    let root_crt = get_cert_asset_path_string("root_ca.chained.crt");
    let inter_crt = get_cert_asset_path_string("inter_ca.crt");
    let inter_crl = get_cert_asset_path_string("inter_ca.crl");
    let ibm_crt = get_cert_asset_path_string(ibm_crt);
    let ibm_crl = get_cert_asset_path_string(ibm_crl);
    let hkd_revoked = load_gen_cert("host_rev.crt");
    let hkd_inv = load_gen_cert("host_invalid_signing_key.crt");
    let hkd_exp = load_gen_cert("host_crt_expired.crt");
    let hkd = load_gen_cert("host.crt");

    let crls = &[ibm_crl, inter_crl];
    let verifier = CertVerifier::new(
        &[ibm_crt, inter_crt],
        if offline { crls } else { &[] },
        &Some(root_crt),
        offline,
    )
    .unwrap();

    let res = verifier.verify(&hkd);
    assert!(res.is_ok(), "Verify failed: res: {res:?}");

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
fn verify_online() {
    verify(false, "ibm.crt", "ibm.crl")
}

#[test]
fn verify_offline() {
    verify(true, "ibm.crt", "ibm.crl")
}

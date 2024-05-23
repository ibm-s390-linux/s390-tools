// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(test)]

use super::{helper, helper::*, *};
use crate::{utils::read_crls, Error, HkdVerifyErrorType::*};
use openssl::{stack::Stack, x509::X509Crl};
use std::path::Path;

use crate::test_utils::*;

// Mock function
pub fn download_first_crl_from_x509(cert: &X509Ref) -> Result<Option<Vec<X509Crl>>> {
    fn mock_download<P: AsRef<Path>>(path: P) -> Result<Vec<X509Crl>> {
        read_crls(std::fs::read(path)?)
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
    let ibm_path = get_cert_asset_path("ibm.crt");
    let inter_path = get_cert_asset_path("inter.crt");
    let crls: [String; 0] = [];

    let store = helper::store_setup(None::<String>, &crls, &[&ibm_path, &inter_path]);
    assert!(store.is_ok());
}

#[test]
fn verify_chain_online() {
    let ibm_crt = get_cert_asset_path("ibm.crt");
    let inter_crt = get_cert_asset_path("inter_ca.crt");
    let root_crt = get_cert_asset_path("root_ca.chained.crt");
    let crls: [String; 0] = [];

    let ret = CertVerifier::new(&[&ibm_crt, &inter_crt], &crls, Some(&root_crt), false);
    assert!(ret.is_ok(), "CertVerifier::new failed: {ret:?}");
}

#[test]
fn verify_chain_offline() {
    let ibm_crt = load_gen_cert("ibm.crt");
    let inter_crl = get_cert_asset_path("inter_ca.crl");
    let inter_crt = load_gen_cert("inter_ca.crt");
    let root_crt = get_cert_asset_path("root_ca.chained.crt");
    let certs: [String; 0] = [];

    let store = helper::store_setup(Some(&root_crt), &[&inter_crl], &certs)
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

fn verify(offline: bool, ibm_crt: &'static str, ibm_crl: &'static str, hkd: &'static str) {
    let root_crt = get_cert_asset_path("root_ca.chained.crt");
    let inter_crt = get_cert_asset_path("inter_ca.crt");
    let inter_crl = get_cert_asset_path("inter_ca.crl");
    let ibm_crt = get_cert_asset_path(ibm_crt);
    let ibm_crl = get_cert_asset_path(ibm_crl);
    let hkd_revoked = load_gen_cert("host_rev.crt");
    let hkd_exp = load_gen_cert("host_crt_expired.crt");
    let hkd = load_gen_cert(hkd);

    let crls = [&ibm_crl, &inter_crl];
    let verifier = CertVerifier::new(
        &[&ibm_crt, &inter_crt],
        if offline { &crls } else { &[] },
        Some(&root_crt),
        offline,
    )
    .unwrap();

    let res = verifier.verify(&hkd);
    assert!(res.is_ok(), "Verify failed: res: {res:?}");

    assert!(matches!(
        verifier.verify(&hkd_revoked),
        Err(Error::HkdVerify(HkdRevoked))
    ));

    assert!(matches!(
        verifier.verify(&hkd_exp),
        Err(Error::HkdVerify(AfterValidity))
    ));
}

#[test]
fn verify_online() {
    verify(false, "ibm.crt", "ibm.crl", "host.crt")
}

#[test]
fn verify_offline() {
    verify(true, "ibm.crt", "ibm.crl", "host.crt")
}

#[test]
fn verify_armonk_crt_online() {
    verify(false, "ibm_armonk.crt", "ibm.crl", "host.crt")
}

#[test]
fn verify_armonk_crt_offline() {
    verify(true, "ibm_armonk.crt", "ibm.crl", "host.crt")
}

#[test]
fn verify_armonk_crl_online() {
    verify(false, "ibm_armonk.crt", "ibm_armonk.crl", "host.crt")
}

#[test]
fn verify_armonk_crl_offline() {
    verify(true, "ibm_armonk.crt", "ibm_armonk.crl", "host.crt")
}

#[test]
fn verify_armonk_hkd_online() {
    verify(false, "ibm_armonk.crt", "ibm_armonk.crl", "host_armonk.crt")
}

#[test]
fn verify_armonk_hkd_offline() {
    verify(true, "ibm_armonk.crt", "ibm_armonk.crl", "host_armonk.crt")
}

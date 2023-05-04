// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(all(feature = "request", feature = "uvsecret"))]
use pv::{
    get_test_asset,
    request::{
        openssl::pkey::{PKey, Public},
        uvsecret::{AddSecretFlags, AddSecretRequest, AddSecretVersion, ExtSecret, GuestSecret},
        BootHdrTags, ReqEncrCtx, Request, SymKey,
    },
    test_utils::get_test_keys,
    uv::ConfigUid,
    Result,
};

const TAGS: BootHdrTags = BootHdrTags::new([1; 64], [2; 64], [3; 64], [4; 16]);
const CUID: ConfigUid = [0x42u8; 16];
const ASSOC_SECRET: [u8; 32] = [0x11; 32];
const ASSOC_ID: &'static str = "add_secret_request";

fn create_asrcb(
    guest_secret: GuestSecret,
    ext_secret: Option<ExtSecret>,
    flags: AddSecretFlags,
    cuid: Option<ConfigUid>,
    hkd: PKey<Public>,
    ctx: &ReqEncrCtx,
) -> Result<Vec<u8>> {
    let mut asrcb = AddSecretRequest::new(AddSecretVersion::One, guest_secret, TAGS, flags);

    if let Some(s) = ext_secret {
        asrcb.set_ext_secret(s)?
    };
    if let Some(c) = cuid {
        asrcb.set_cuid(c);
    };

    asrcb.add_hostkey(hkd);
    Ok(asrcb.encrypt(ctx)?)
}

fn get_crypto() -> (PKey<Public>, ReqEncrCtx) {
    let (cust_key, host_key) = get_test_keys();
    let ctx = ReqEncrCtx::new_aes_256(
        Some([0x55; 12]),
        Some(cust_key),
        Some(SymKey::Aes256([0x17; 32].into())),
    )
    .unwrap();
    (host_key, ctx)
}

fn gen_asrcb<E>(
    guest_secret: GuestSecret,
    ext_secret: E,
    flags: AddSecretFlags,
    cuid: bool,
) -> Result<Vec<u8>>
where
    E: Into<Option<ExtSecret>>,
{
    let (host_key, ctx) = get_crypto();
    let cuid = match cuid {
        true => Some(CUID.into()),
        false => None,
    };
    create_asrcb(
        guest_secret,
        ext_secret.into(),
        flags,
        cuid.into(),
        host_key,
        &ctx,
    )
}

fn association() -> GuestSecret {
    GuestSecret::association(ASSOC_ID, ASSOC_SECRET).unwrap()
}

fn ext_simple() -> ExtSecret {
    ExtSecret::Simple([0x17; 32].into())
}

fn ext_derived() -> ExtSecret {
    ExtSecret::Derived([0; 32].into())
}

fn no_flag() -> AddSecretFlags {
    AddSecretFlags::default()
}

#[test]
fn null_none_default_cuid_one() {
    let asrcb = gen_asrcb(GuestSecret::Null, None, no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/null_none_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn assoc_none_default_cuid_one() {
    let asrcb = gen_asrcb(association(), None, no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/assoc_none_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn null_simple_default_cuid_one() {
    let asrcb = gen_asrcb(GuestSecret::Null, ext_simple(), no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/null_simple_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn assoc_simple_default_cuid_one() {
    let asrcb = gen_asrcb(association(), ext_simple(), no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/assoc_simple_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn null_derived_default_cuid_one() {
    let asrcb = gen_asrcb(GuestSecret::Null, ext_derived(), no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/null_derived_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn assoc_derived_default_cuid_one() {
    let asrcb = gen_asrcb(association(), ext_derived(), no_flag(), true).unwrap();
    let exp = get_test_asset!("exp/asrcb/assoc_derived_default_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn null_none_dump_cuid_one() {
    let mut flags = no_flag();
    flags.set_disable_dump();
    let asrcb = gen_asrcb(GuestSecret::Null, None, flags, true).unwrap();
    let exp = get_test_asset!("exp/asrcb/null_none_dump_cuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn null_none_default_ncuid_one() {
    let asrcb = gen_asrcb(GuestSecret::Null, None, no_flag(), false).unwrap();
    let exp = get_test_asset!("exp/asrcb/null_none_default_ncuid_one");
    assert_eq!(asrcb, exp);
}

#[test]
fn null_none_default_cuid_seven() {
    let (hkd, ctx) = get_crypto();
    let mut asrcb =
        AddSecretRequest::new(AddSecretVersion::One, GuestSecret::Null, TAGS, no_flag());
    (0..7).for_each(|_| asrcb.add_hostkey(hkd.clone()));
    asrcb.set_cuid(CUID.into());
    let asrcb = asrcb.encrypt(&ctx).unwrap();

    let exp = get_test_asset!("exp/asrcb/null_none_default_cuid_seven");
    assert_eq!(asrcb, exp);
}

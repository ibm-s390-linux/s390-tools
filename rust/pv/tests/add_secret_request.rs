// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::Private,
};
use s390_pv::{
    get_test_asset,
    request::{
        openssl::pkey::{PKey, Public},
        BootHdrTags, ReqEncrCtx, Request, SymKey,
    },
    secret::{
        verify_asrcb_and_get_user_data, AddSecretFlags, AddSecretRequest, AddSecretVersion,
        ExtSecret, GuestSecret,
    },
    test_utils::get_test_keys,
    uv::ConfigUid,
    Result,
};

const TAGS: BootHdrTags = BootHdrTags::new([1; 64], [2; 64], [3; 64], [4; 16]);
const CUID: ConfigUid = [0x42u8; 16];
const ASSOC_SECRET: [u8; 32] = [0x11; 32];
const ASSOC_ID: &str = "add_secret_request";

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
    asrcb.encrypt(ctx)
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
        true => Some(CUID),
        false => None,
    };
    create_asrcb(guest_secret, ext_secret.into(), flags, cuid, host_key, &ctx)
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

fn create_signed_asrcb(skey: PKey<Private>, user_data: Vec<u8>) -> Vec<u8> {
    let (host_key, ctx) = get_crypto();
    let mut asrcb =
        AddSecretRequest::new(AddSecretVersion::One, GuestSecret::Null, TAGS, no_flag());

    asrcb.add_hostkey(host_key);
    asrcb.set_user_data(user_data, Some(skey)).unwrap();
    asrcb.encrypt(&ctx).unwrap()
}

#[test]
fn null_none_default_ncuid_one_user_unsgn() {
    let user_data_orig = vec![0x56; 0x183];
    let (host_key, ctx) = get_crypto();
    let mut asrcb =
        AddSecretRequest::new(AddSecretVersion::One, GuestSecret::Null, TAGS, no_flag());

    asrcb.add_hostkey(host_key);
    asrcb.set_user_data(user_data_orig.clone(), None).unwrap();
    let asrcb = asrcb.encrypt(&ctx).unwrap();

    let user_data = verify_asrcb_and_get_user_data(asrcb, None).unwrap();

    assert_eq!(
        user_data_orig.as_slice(),
        &user_data.as_ref().unwrap()[..user_data_orig.len()]
    );
}
#[test]
fn null_none_default_ncuid_one_user_ec() {
    let (usr_sgn_key, _) = get_test_keys();

    let usr_vrfy_key = usr_sgn_key.ec_key().unwrap();
    let usr_vrfy_key = usr_vrfy_key.public_key();
    let usr_vrfy_key = PKey::from_ec_key(
        EcKey::from_public_key(
            &EcGroup::from_curve_name(Nid::SECP521R1).unwrap(),
            usr_vrfy_key,
        )
        .unwrap(),
    )
    .unwrap();

    let user_data_orig = vec![0x56; 0x100];
    let asrcb = create_signed_asrcb(usr_sgn_key, user_data_orig.clone());

    let user_data = verify_asrcb_and_get_user_data(asrcb, Some(usr_vrfy_key)).unwrap();
    assert_eq!(
        user_data_orig.as_slice(),
        &user_data.as_ref().unwrap()[..user_data_orig.len()]
    );
}

#[test]
fn null_none_default_ncuid_one_user_rsa2048() {
    let usr_sgn_key = get_test_asset!("keys/rsa2048key.pem");
    let usr_sgn_key = PKey::private_key_from_pem(usr_sgn_key).unwrap();
    let user_data_orig = vec![0x56; 0x100];
    let asrcb = create_signed_asrcb(usr_sgn_key, user_data_orig.clone());

    let usr_vrfy_key = get_test_asset!("keys/rsa2048key.pub.pem");
    let usr_vrfy_key = PKey::public_key_from_pem(usr_vrfy_key).unwrap();

    let user_data = verify_asrcb_and_get_user_data(asrcb, Some(usr_vrfy_key)).unwrap();
    assert_eq!(
        user_data_orig.as_slice(),
        &user_data.as_ref().unwrap()[..user_data_orig.len()]
    );
}

#[test]
fn null_none_default_ncuid_one_user_rsa3072() {
    let usr_sgn_key = get_test_asset!("keys/rsa3072key.pem");
    let usr_sgn_key = PKey::private_key_from_pem(usr_sgn_key).unwrap();
    let user_data_orig = vec![0x56; 0x80];
    let asrcb = create_signed_asrcb(usr_sgn_key, user_data_orig.clone());

    let usr_vrfy_key = get_test_asset!("keys/rsa3072key.pub.pem");
    let usr_vrfy_key = PKey::public_key_from_pem(usr_vrfy_key).unwrap();

    let user_data = verify_asrcb_and_get_user_data(asrcb, Some(usr_vrfy_key)).unwrap();
    assert_eq!(
        user_data_orig.as_slice(),
        &user_data.as_ref().unwrap()[..user_data_orig.len()]
    );
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
    asrcb.set_cuid(CUID);
    let asrcb = asrcb.encrypt(&ctx).unwrap();

    let exp = get_test_asset!("exp/asrcb/null_none_default_cuid_seven");
    assert_eq!(asrcb, exp);
}

#[test]
fn verify_no_user_data() {
    let req = get_test_asset!("exp/asrcb/null_none_default_ncuid_one");
    assert!(matches!(
        verify_asrcb_and_get_user_data(req.to_vec(), None),
        Ok(None)
    ))
}

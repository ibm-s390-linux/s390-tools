use crate::assert_size;
use crate::{
    crypto::{sign_msg, verify_signature},
    req::BinReqValues,
    request::{
        openssl::pkey::{HasParams, HasPublic, Id, PKey, PKeyRef, Private, Public},
        RequestMagic,
    },
    secret::{AddSecretMagic, AddSecretRequest, AddSecretVersion, UserDataType},
    Error, Result,
};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use zerocopy::{AsBytes, BigEndian, FromBytes, FromZeroes, U16};

/// User data.
///
/// User defined data can be:
/// - 512 bytes arbitrary data
/// - 256 bytes arbitrary data + EC(secp521r1) signature
/// ```none
/// LAYOUT
/// |------------------------|
/// | user-data (256)        |
/// | ec signature (139)     |
/// | reserved (5)           |
/// | signature size (2) (BE)|
/// | reserved (110)         |
/// |------------------------|
/// ```
/// - 256 bytes arbitrary data + RSA2048 signature
/// ```none
/// LAYOUT
/// |---------------------|
/// | user-data (256)     |
/// | rsa signature (256) |
/// |---------------------|
/// ```
/// - 128 bytes arbitrary data + RSA3072 signature
/// ```none
/// LAYOUT
/// |---------------------|
/// | user-data (128)     |
/// | rsa signature (384) |
/// |---------------------|
/// ```
///
/// Ensures that the data+signature fits into 512 bytes
/// must be created via functions!
#[derive(Debug, Clone)]
pub(super) enum UserData {
    Null,
    Unsigned(Vec<u8>),
    Signed(SignedUserData),
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, FromZeroes)]
struct EcUserData {
    data: [u8; 256],
    signature: [u8; EC_SIGN_MAX_SIZE],
    res_18b: [u8; 5],
    sgn_size: U16<BigEndian>,
    res_192: [u8; 110],
}
assert_size!(EcUserData, USER_DATA_SIZE);
const USER_DATA_SIZE: usize = 0x200;
const EC_SIGN_MAX_SIZE: usize = 139;

impl EcUserData {
    // Sets the signature to this data.
    //
    //# Panic
    // Panics if `sgn` is longer than 139 bytes
    fn set_signature(&mut self, sgn: &[u8]) {
        debug_assert!(sgn.len() <= EC_SIGN_MAX_SIZE);
        self.signature.fill(0);
        self.signature[..sgn.len()].copy_from_slice(sgn);

        self.res_18b.fill(0);
        self.sgn_size = (sgn.len() as u16).into();
        self.res_192.fill(0);
    }
}

#[derive(Debug, Clone)]
pub(super) struct SignedUserData {
    sign_key: PKey<Private>,
    data: Vec<u8>,
}

impl UserData {
    const USER_DATA_SIZE: usize = 0x200;

    fn user_data_type<P: HasPublic>(sign_key: &PKeyRef<P>) -> Result<UserDataType> {
        fn check_curve<P: HasParams>(pkey: &PKeyRef<P>) -> Result<bool> {
            let nid = pkey.ec_key()?.group().curve_name();
            match nid {
                Some(nid) => Ok(nid == Nid::SECP521R1),
                None => Ok(false),
            }
        }
        match sign_key.id() {
            Id::EC if check_curve(sign_key)? => Ok(UserDataType::SgnEcSECP521R1),
            Id::RSA if sign_key.rsa()?.size() == 2048 / 8 => Ok(UserDataType::SgnRsa2048),
            Id::RSA if sign_key.rsa()?.size() == 3072 / 8 => Ok(UserDataType::SgnRsa3072),
            _ => Err(Error::BinAsrcbUnsupportedUserDataSgnKey),
        }
    }

    pub(super) fn magic(&self) -> RequestMagic {
        let magic: AddSecretMagic = self.data_type().into();
        magic.get()
    }

    /// Creates new user data
    ///
    /// Verifies that the provided data + signature fits into 512 bytes
    ///
    /// # Error
    /// An error is reported if the provided data and the signature would not fit into 512 bytes
    /// An error is reported if the key is not of type RSA (2048|3072) or EC(specp521r1)
    pub(super) fn new(sign_key: Option<PKey<Private>>, data: Vec<u8>) -> Result<Self> {
        let sign_key = match sign_key {
            None => {
                return match data.len() > UserDataType::Unsigned.max() {
                    true => Err(Error::AsrcbInvSgnUserData(UserDataType::Unsigned)),
                    false => Ok(Self::Unsigned(data)),
                };
            }
            Some(skey) => skey,
        };

        let kind = Self::user_data_type(&sign_key)?;

        // does the data fit into the arbitrary buffer?
        if data.len() > kind.max() {
            return Err(Error::AsrcbInvSgnUserData(kind));
        }

        Ok(Self::Signed(SignedUserData { sign_key, data }))
    }

    /// Signs data in buf, writes signature to buf+user_data_offset+sign_offset if applicable.
    ///
    /// Uses [`MessageDigest::sha512`] as digest. Does not modify the abritary user data buffer.
    ///
    /// * buf: user data buffer, must be at least 512 bytes long
    ///
    /// # Panic
    /// panics if `buf` is smaller than 512 bytes
    ///
    /// # Errors
    ///  Returns an error if signature could not be calculated.
    ///  It is considered no error if no signature is required by user data type
    pub(super) fn sign(&self, buf: &mut [u8], user_data_offset: usize) -> Result<()> {
        // get signing info or return if no signature is required
        let signed_data = match self {
            UserData::Null | UserData::Unsigned(_) => return Ok(()),
            UserData::Signed(s) => s,
        };
        debug_assert!(buf.len() >= USER_DATA_SIZE);

        // clear the signature area
        let sgn_offset = user_data_offset + self.data_type().max();
        buf[sgn_offset..user_data_offset + USER_DATA_SIZE].fill(0);

        // calculate signature
        let sgn = sign_msg(&signed_data.sign_key, MessageDigest::sha512(), buf)?;

        // insert signature
        if let UserDataType::SgnEcSECP521R1 = self.data_type() {
            // Panic: will not panic buffer is 512+ bytes long
            let buf_ec = EcUserData::mut_from_prefix(&mut buf[user_data_offset..]).unwrap();
            buf_ec.set_signature(&sgn);
        } else {
            // Panic: will not panic buffer is 512+ bytes long
            buf[sgn_offset..sgn_offset + sgn.len()].copy_from_slice(&sgn);
        }
        Ok(())
    }

    fn data_type(&self) -> UserDataType {
        match self {
            Self::Null => UserDataType::Null,
            Self::Unsigned(_) => UserDataType::Unsigned,
            Self::Signed(data) => Self::user_data_type(&data.sign_key).unwrap(),
        }
    }

    /// returns a slice for the abitraty user data as first tuple part if User data is available
    /// the second part contains a vector, created on the fly, which contains enough zeros to fill
    /// the missing bytes to fill 512 bytes of space or None if the first slice already contains
    /// 512 bytes
    pub(super) fn data(&self) -> (Option<&[u8]>, Option<Vec<u8>>) {
        let buf = match self {
            UserData::Null => None,
            UserData::Unsigned(d) => Some(d),
            UserData::Signed(SignedUserData { data, .. }) => Some(data),
        };

        let remaining_size = Self::USER_DATA_SIZE - buf.map(|b| b.len()).unwrap_or(0);
        let remaining = match remaining_size > 0 {
            true => Some(vec![0; remaining_size]),
            false => None,
        };

        (buf.map(|b| b.as_ref()), remaining)
    }
}

fn format_vrfy_key(key: &PKeyRef<Public>) -> String {
    let id = key.id();
    match key.rsa() {
        Ok(key) => format!("RSA {}", key.size() * 8),
        Err(_) if id == Id::EC => "EC".to_string(),
        Err(_) => "Unknown".to_string(),
    }
}

fn check_key_format(kind: UserDataType, key: &PKeyRef<Public>) -> Result<()> {
    let other_kind =
        UserData::user_data_type(key).map_err(|_| Error::AsrcbUserDataKeyMismatch {
            key: format_vrfy_key(key),
            kind,
        })?;
    if other_kind == kind {
        Ok(())
    } else {
        Err(Error::AsrcbUserDataKeyMismatch {
            key: format_vrfy_key(key),
            kind,
        })
    }
}

/// Verify the user data contained in the add-secret request.
///
/// First checks that the provided data contains a sound add-secret request.
/// Then performs the inverse action that happened during the add-secret generation with user-data
/// signature:
/// - extract and replace the signature with zeros
/// - verify the signature of the request until, but not including the request tag
///
/// # Returns
///
/// Extracrted user-data if available
///
/// # Errors
///
/// returns an error if
/// - No sound add-secret request presented
/// - Sinned user-data indicated, but no key provided
/// - Another keytype provided than indicated in the request
/// - Signature could not be verified by the provided key
/// - any OpenSSL error that might happen during the verification process
pub fn verify_asrcb_and_get_user_data(
    mut asrcb: Vec<u8>,
    key: Option<PKey<Public>>,
) -> Result<Option<Vec<u8>>> {
    // check that the provided buffer contains an Add Secret request
    let magic = AddSecretMagic::try_from_bytes(&asrcb)?;
    let req = BinReqValues::get(&asrcb)?;
    if req.version() != AddSecretVersion::One as u32 {
        return Err(Error::BinAsrcbInvVersion);
    }

    // preventing the two lines after the truncate from panicking
    let req_len = req.len();
    if asrcb.len() < req_len
        || req_len < AddSecretRequest::V1_USER_DATA_OFFS + UserData::USER_DATA_SIZE
    {
        return Err(pv_core::Error::NoAsrcb.into());
    }
    // forget the tag (and all additional data that might be behind the tag)
    asrcb.truncate(req_len - BinReqValues::TAG_LEN);
    // get a mutable refrenence on the 512 bytes of user data
    let (_, user_data) = asrcb.split_at_mut(AddSecretRequest::V1_USER_DATA_OFFS);
    let user_data = &mut user_data[..UserData::USER_DATA_SIZE];

    // depending on the user_data_type do:
    // Null -> exit w/o user data
    // Unsigned -> exit return all user data
    // Signed ->
    //     - check that provided key matches user data keytype
    //     - extract user data& signature
    let (key, user_data) = match (key, magic.kind()) {
        (_, UserDataType::Null) => return Ok(None),
        (None, UserDataType::Unsigned) => return Ok(Some(user_data.to_vec())),
        (Some(key), UserDataType::Unsigned) => {
            return Err(Error::AsrcbUserDataKeyMismatch {
                key: format_vrfy_key(&key),
                kind: UserDataType::Unsigned,
            })
        }
        (Some(key), _) => {
            check_key_format(magic.kind(), &key)?;
            (key, VerifiedUserData::new(user_data, magic.kind()))
        }
        (None, _) => return Err(Error::BinAsrcbNoUserDataSgnKey),
    };

    match verify_signature(&key, MessageDigest::sha512(), &asrcb, user_data.signature())? {
        false => Err(Error::AsrcbUserDataSgnFail),
        true => Ok(Some(user_data.into())),
    }
}

// Internal representation of the 512 bytes of user-data, signing-algorithm agnostic
struct VerifiedUserData {
    data: Vec<u8>,
    signature: Vec<u8>,
}

impl VerifiedUserData {
    /// Reads user-data from buf depending on the indicated user data type.
    /// Overwrites the signature in the buf with zeros.
    ///
    /// #Panics
    ///
    /// Panics it provided buffer is smaller that 512 bytes or kind is Null or Unsigned
    fn new(buf: &mut [u8], kind: UserDataType) -> Self {
        assert!(buf.len() >= 0x200);

        let (ret, sgn) = match kind {
            UserDataType::SgnEcSECP521R1 => {
                let EcUserData {
                    data,
                    signature,
                    sgn_size,
                    ..
                } = EcUserData::mut_from_prefix(buf).unwrap();
                let data_len: usize = data.len();
                let data = data.to_vec();
                let mut signature = signature.to_vec();
                signature.truncate(sgn_size.get() as usize);
                (Self { data, signature }, &mut buf[data_len..])
            }
            UserDataType::SgnRsa2048 => (
                Self {
                    data: buf[..0x100].to_vec(),
                    signature: buf[0x100..].to_vec(),
                },
                &mut buf[0x100..],
            ),
            UserDataType::SgnRsa3072 => (
                Self {
                    data: buf[..0x80].to_vec(),
                    signature: buf[0x80..].to_vec(),
                },
                &mut buf[0x80..],
            ),
            UserDataType::Null => unreachable!(),
            UserDataType::Unsigned => unreachable!(),
        };

        // overwrite signature field with zeros
        sgn.fill(0);
        ret
    }

    fn signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

impl From<VerifiedUserData> for Vec<u8> {
    fn from(value: VerifiedUserData) -> Self {
        value.data
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{get_test_asset, test_utils::get_test_keys};

    #[test]
    fn sign_null() {
        let mut buf = vec![17; 0x200];

        let user_data = UserData::Null;
        let (data, _) = user_data.data();
        assert!(data.is_none());

        user_data.sign(&mut buf, 0).unwrap();

        // sign should not touch the buffer
        assert_eq!(buf, vec![17; 0x200]);
    }

    #[test]
    fn sign_unsigned() {
        let user_data = UserData::Unsigned(vec![0x11; 0x200]);
        let (data, _) = user_data.data();
        assert_eq!(data.unwrap(), &[0x11; 0x200]);

        let mut buf = vec![17; 0x200];
        user_data.sign(&mut buf, 0).unwrap();

        // sign should not touch the buffer
        assert_eq!(buf, vec![17; 0x200]);
    }

    #[test]
    fn sign_rsa2048() {
        let rsa = get_test_asset!("keys/rsa2048key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();

        let mut buf = vec![0x17; 0x200];

        let user_data = UserData::new(Some(rsa.clone()), vec![0x11; 0x100]).unwrap();
        let (data, _) = user_data.data();
        let data = data.unwrap();
        buf[..0x100].copy_from_slice(data);

        user_data.sign(&mut buf, 0).unwrap();

        let vrf_user_data = VerifiedUserData::new(&mut buf, UserDataType::SgnRsa2048);
        let res = verify_signature(
            &rsa,
            MessageDigest::sha512(),
            &buf,
            vrf_user_data.signature(),
        )
        .unwrap();
        assert!(res);
    }

    #[test]
    fn sign_rsa3072() {
        let rsa = get_test_asset!("keys/rsa3072key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();

        let mut buf = vec![0x17; 0x200];

        let user_data = UserData::new(Some(rsa.clone()), vec![0x11; 0x80]).unwrap();
        let (data, _) = user_data.data();
        let data = data.unwrap();
        buf[..0x80].copy_from_slice(data);

        user_data.sign(&mut buf, 0).unwrap();

        let vrf_user_data = VerifiedUserData::new(&mut buf, UserDataType::SgnRsa3072);
        let res = verify_signature(
            &rsa,
            MessageDigest::sha512(),
            &buf,
            vrf_user_data.signature(),
        )
        .unwrap();
        assert!(res);
    }

    #[test]
    fn sign_rsa4096_fail() {
        let rsa = get_test_asset!("keys/rsa4096key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();

        let user_data = UserData::new(Some(rsa.clone()), vec![]);
        assert!(matches!(
            user_data.unwrap_err(),
            Error::BinAsrcbUnsupportedUserDataSgnKey
        ));
    }

    #[test]
    fn sign_ec() {
        let (ec, _) = get_test_keys();

        let mut buf = vec![0x11; 0x200];

        let user_data = UserData::new(Some(ec.clone()), vec![0x11; 0x80]).unwrap();
        let (data, _) = user_data.data();
        let data = data.unwrap();
        buf[..0x80].copy_from_slice(data);

        user_data.sign(&mut buf, 0).unwrap();
        let buf_ec = EcUserData::mut_from(&mut buf).unwrap();
        let EcUserData {
            data,
            signature,
            res_18b,
            sgn_size,
            res_192,
        } = buf_ec;
        assert_eq!(data, &[0x11u8; 256]);
        assert_ne!(signature, &[0x11u8; 139]);
        assert_eq!(res_18b, &[0u8; 5]);
        assert!(sgn_size.get() <= 139);
        assert_eq!(res_192, &[0u8; 110]);

        let vrf_user_data = VerifiedUserData::new(&mut buf, UserDataType::SgnEcSECP521R1);
        let res = verify_signature(
            &ec,
            MessageDigest::sha512(),
            &buf,
            vrf_user_data.signature(),
        )
        .unwrap();
        assert!(res);
    }

    #[test]
    fn sign_ec_fail() {
        let ec = get_test_asset!("keys/ecsecp256k1.pem");
        let ec = PKey::private_key_from_pem(ec).unwrap();

        let user_data = UserData::new(Some(ec.clone()), vec![]);
        assert!(matches!(
            user_data.unwrap_err(),
            Error::BinAsrcbUnsupportedUserDataSgnKey
        ));
    }

    #[test]
    fn check_format() {
        let (_, ec) = get_test_keys();
        check_key_format(UserDataType::SgnEcSECP521R1, &ec).unwrap();
        let res = check_key_format(UserDataType::SgnRsa2048, &ec);
        assert!(matches!(res, Err(Error::AsrcbUserDataKeyMismatch { .. })));

        let rsa = get_test_asset!("keys/rsa2048key.pub.pem");
        let rsa = PKey::public_key_from_pem(rsa).unwrap();
        check_key_format(UserDataType::SgnRsa2048, &rsa).unwrap();

        let rsa = get_test_asset!("keys/rsa3072key.pub.pem");
        let rsa = PKey::public_key_from_pem(rsa).unwrap();
        check_key_format(UserDataType::SgnRsa3072, &rsa).unwrap();
        let res = check_key_format(UserDataType::SgnRsa2048, &rsa);
        assert!(matches!(res, Err(Error::AsrcbUserDataKeyMismatch { .. })));

        let rsa = get_test_asset!("keys/rsa4096key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();
        let rsa = PKey::public_key_from_pem(&rsa.public_key_to_pem().unwrap()).unwrap();
        let res = check_key_format(UserDataType::SgnRsa2048, &rsa);
        assert!(matches!(res, Err(Error::AsrcbUserDataKeyMismatch { .. })));
    }

    #[test]
    fn kind() {
        let (ec, _) = get_test_keys();
        let kind = UserData::user_data_type(&ec).unwrap();
        assert_eq!(kind, UserDataType::SgnEcSECP521R1);

        let rsa = get_test_asset!("keys/rsa2048key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();
        let kind = UserData::user_data_type(&rsa).unwrap();
        assert_eq!(kind, UserDataType::SgnRsa2048);

        let rsa = get_test_asset!("keys/rsa3072key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();
        let kind = UserData::user_data_type(&rsa).unwrap();
        assert_eq!(kind, UserDataType::SgnRsa3072);

        let rsa = get_test_asset!("keys/rsa4096key.pem");
        let rsa = PKey::private_key_from_pem(rsa).unwrap();
        let kind = UserData::user_data_type(&rsa).unwrap_err();
        assert!(matches!(kind, Error::BinAsrcbUnsupportedUserDataSgnKey));
    }

    #[test]
    fn new() {
        let (ec, _) = get_test_keys();
        let user_data = UserData::new(
            Some(ec.clone()),
            vec![1; UserDataType::SgnEcSECP521R1.max()],
        )
        .unwrap();
        assert!(matches!(user_data, UserData::Signed(_)));

        let user_data = UserData::new(Some(ec), vec![1; UserDataType::SgnEcSECP521R1.max() + 1]);
        assert!(matches!(
            user_data,
            Err(Error::AsrcbInvSgnUserData(UserDataType::SgnEcSECP521R1))
        ));

        let user_data = UserData::new(None, vec![1; UserDataType::Unsigned.max()]).unwrap();
        assert!(matches!(user_data, UserData::Unsigned(_)));

        let user_data = UserData::new(None, vec![1; UserDataType::Unsigned.max() + 1]);
        assert!(matches!(
            user_data,
            Err(Error::AsrcbInvSgnUserData(UserDataType::Unsigned))
        ));
    }
    #[test]
    fn data() {
        let (ec, _) = get_test_keys();
        let data_in = vec![1; UserDataType::SgnEcSECP521R1.max()];
        let user_data = UserData::new(Some(ec.clone()), data_in.clone()).unwrap();
        let exp_pad = Some(vec![0; UserData::USER_DATA_SIZE - data_in.len()]);

        let (data_out, pad) = user_data.data();
        assert_eq!(data_out, Some(data_in.as_ref()));
        assert_eq!(pad, exp_pad);

        let data_in = vec![1; UserDataType::SgnEcSECP521R1.max() - 1];
        let user_data = UserData::new(Some(ec.clone()), data_in.clone()).unwrap();
        let exp_pad = Some(vec![0; UserData::USER_DATA_SIZE - data_in.len()]);

        let (data_out, pad) = user_data.data();
        assert_eq!(data_out, Some(data_in.as_ref()));
        assert_eq!(pad, exp_pad);
    }
}

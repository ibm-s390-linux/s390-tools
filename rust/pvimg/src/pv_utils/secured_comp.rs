// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{
    fmt::{Debug, Formatter},
    io::{Read, Write},
    rc::Rc,
};

use log::debug;
use openssl::{
    bn::BigNum,
    cipher::{Cipher, CipherRef},
    cipher_ctx::{CipherCtx, CipherCtxRef},
    hash::{Hasher, MessageDigest},
    nid::Nid,
};
use pv::request::{Confidential, SymKey, SymKeyType};

use super::{try_copy_slice_to_array, Layout};
use crate::pv_utils::{
    error::{Error, PvError, Result},
    se_hdr::{ComponentMetadata, ComponentMetadataV1},
    Interval,
};

#[allow(unused)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Padding,
}

fn update_ald_digest(hasher: &mut Hasher, interval: &Interval, chunk_size: usize) -> Result<usize> {
    let mut num_chunks = 0;

    for addr in (interval.start..interval.stop).step_by(chunk_size) {
        let addr_be_data = addr.to_be_bytes();

        hasher.update(&addr_be_data)?;
        num_chunks += 1;
    }
    Ok(num_chunks)
}

pub struct PrepareSecuredComponentArgs<'a> {
    pub(crate) addr: u64,
    pub(crate) cipher: &'a CipherRef,
    pub(crate) mode: Mode,
    pub(crate) key: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) chunk_size: usize,
}

pub struct MetadataArgs<'a> {
    pub(crate) content_hasher: Option<&'a mut Hasher>,
    pub(crate) tweak_hasher: Option<&'a mut Hasher>,
    pub(crate) address_hasher: Option<&'a mut Hasher>,
    pub(crate) num_chunks: Option<&'a mut usize>,
    pub(crate) max_component_size: Option<usize>,
    pub(crate) input_size: usize,
    pub(crate) padded_input_size: usize,
    pub(crate) output_size: usize,
}

/// This functions tries to read the exact number of bytes required to fill
/// `buf`.
///
/// # Errors
///
/// If this function encounters an EOF before completely filling the buffer, it
/// returns an error of the kind [`std::io::ErrorKind::UnexpectedEof`]. The
/// contents of `buf` are unspecfied in this case.
fn own_read_exact<R: Read + ?Sized>(reader: &mut R, mut buf: &mut [u8]) -> std::io::Result<usize> {
    let mut data_read = 0;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
                data_read += n;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(data_read)
}

/// This function is used for prepare a "secured component" used in the Secure Execution
/// context. It adds padding if needed, encrypts the components and calculates
/// the PLD and TLD.
pub fn prepare_component<R: Read, W: Write>(
    crypto_args: &PrepareSecuredComponentArgs,
    src: &mut R,
    dst: &mut W,
    mut opt_data: Option<&mut MetadataArgs>,
) -> Result<()> {
    let PrepareSecuredComponentArgs {
        addr,
        cipher,
        mode,
        key,
        iv,
        chunk_size,
    } = *crypto_args;
    let mut chunk_data = vec![0_u8; chunk_size];
    let mut output_data = vec![0_u8; chunk_data.len()];
    let mut chunks_count: usize = 0;
    let mut count;

    let mut tweak_num = BigNum::from_slice(iv)?;
    let mut ctx = if matches!(mode, Mode::Decrypt) || matches!(mode, Mode::Encrypt) {
        Some(CipherCtx::new()?)
    } else {
        None
    };

    let init_func = match mode {
        // The value for Mode::Padding will never be actually used.
        Mode::Encrypt | Mode::Padding => CipherCtxRef::encrypt_init,
        Mode::Decrypt => CipherCtxRef::decrypt_init,
    };

    if let Some(ref mut ctx) = &mut ctx {
        assert!(chunk_size % cipher.block_size() == 0, "Invalid chunk size");

        init_func(ctx, Some(cipher), None, None)?;

        if key.len() != cipher.key_length() {
            debug!("Setting new key length: {}", key.len());
            ctx.set_key_length(key.len())?;
        }
        if iv.len() != cipher.iv_length() {
            debug!("Setting new IV length: {}", iv.len());
            ctx.set_iv_length(iv.len())?;
        }

        // Set key
        init_func(ctx, None, Some(key), None)?;
    };

    loop {
        let new_tweak = tweak_num.to_vec_padded(iv.len().try_into()?)?;

        // Set a new tweak
        if let Some(ref mut ctx) = &mut ctx {
            init_func(ctx, None, None, Some(&new_tweak))?;
        }

        // Read input data
        let read_count = own_read_exact(src, &mut chunk_data)?;
        // EOF has been reached
        if read_count == 0 {
            // A chunk was read before and EOF was reached => it was not an
            // empty file and therefore break the loop.
            if chunks_count != 0 {
                break;
            }
        }

        let input_slice = &chunk_data[..];

        // Encrypt
        if let Some(ref mut ctx) = ctx {
            count = ctx.cipher_update(input_slice, Some(&mut output_data))?;
        } else {
            output_data.copy_from_slice(input_slice);
            count = input_slice.len();
        }

        // Write output data and check if it fits in the image layout
        let output_slice = &output_data[..count];
        if let Some(ops) = opt_data.as_mut() {
            let output_size = ops
                .output_size
                .checked_add(output_slice.len())
                .ok_or(Error::UnexpectedOverflow)?;

            if let Some(max_output_size) = ops.max_component_size {
                if output_size > max_output_size {
                    return Err(Error::PreparedComponentTooLarge {
                        output_size,
                        max_output_size,
                    });
                }
            }
            ops.output_size = output_size;

            // Calculate input size
            ops.input_size = ops
                .input_size
                .checked_add(read_count)
                .ok_or(Error::UnexpectedOverflow)?;

            // Calculate padded input size
            ops.padded_input_size = ops
                .padded_input_size
                .checked_add(input_slice.len())
                .ok_or(Error::UnexpectedOverflow)?;

            // Calculate PLD
            if let Some(ref mut hasher) = ops.content_hasher {
                hasher.update(output_slice)?;
            }

            // Calculate TLD
            if let Some(ref mut hasher) = ops.tweak_hasher {
                hasher.update(&new_tweak)?;
            }
        }

        dst.write_all(output_slice)?;
        chunks_count = chunks_count
            .checked_add(1)
            .ok_or(Error::UnexpectedOverflow)?;

        // Prepare for the next chunk:
        // * Calculate new tweak
        // * Reset chunk data to zeroes
        tweak_num.add_word(chunk_size.try_into()?)?;
        chunk_data.fill(0x0);
    }

    if let Some(ref mut ctx) = &mut ctx {
        count = ctx.cipher_final(&mut output_data)?;
    } else {
        count = 0;
    }
    let output_slice = &output_data[..count];
    dst.write_all(output_slice)?;

    if let Some(ops) = opt_data.as_mut() {
        // Calculate output size
        let output_size = ops
            .output_size
            .checked_add(output_slice.len())
            .ok_or(Error::UnexpectedOverflow)?;

        if let Some(max_output_size) = ops.max_component_size {
            if output_size > max_output_size {
                return Err(Error::PreparedComponentTooLarge {
                    output_size,
                    max_output_size,
                });
            }
        }
        ops.output_size = output_size;

        // Calculate PLD
        if let Some(ref mut hasher) = ops.content_hasher {
            hasher.update(output_slice)?;
        }

        // Calculate ALD
        if let Some(ref mut hasher) = ops.address_hasher {
            update_ald_digest(
                hasher,
                &Interval::new_with_size(addr, output_size.try_into()?)?,
                chunk_size,
            )?;
        }

        // Update the total number of prepared chunks.
        if let Some(ref mut num_chunks) = ops.num_chunks {
            **num_chunks = num_chunks
                .checked_add(chunks_count)
                .ok_or(Error::UnexpectedOverflow)?;
        }
    }

    Ok(())
}

/// A trait for dealing with (secured) components.
pub trait ComponentTrait<T>: Debug + Read {
    /// Returns if the component is used in secure mode.
    fn secure_mode(&self) -> bool;

    /// Returns the component type.
    fn kind(&self) -> T;
}

/// Struct for representing a secured component that is going to be unpacked by
/// the Ultravisor.
#[derive(Debug, PartialEq, Eq)]
pub struct SecuredComponent {
    /// Source of the prepared (encrypted) component
    pub src: Rc<Interval>,
    /// Size of the unprepared (unencrypted) component.
    pub original_size: usize,
    /// Tweak or IV used for the (de/en)cryption of the component.
    tweak_or_iv: Vec<u8>,
}

impl SecuredComponent {
    pub fn tweak(&self) -> &[u8] {
        self.tweak_or_iv.as_slice()
    }
}

/// A builder that is used to prepare a [`SecuredComponent`].
pub struct SecuredComponentBuilder {
    /// Expert mode, in example the secured components encryption key and be set
    /// manually. By default disabled.
    expert_mode: bool,
    /// Chunk size, currently only 4096 bytes is supported by the Ultravisor.
    chunk_size: usize,

    /// Determines whether a secured component needs to be encrypted.
    encrypt: bool,
    /// Determines which cipher will be used for the encryption.
    cipher: &'static CipherRef,
    /// Key used for the encryption of the components.
    comp_key: SymKey,

    // Cached values
    /// Number of chunks already prepared by this [`Self`].
    num_chunks: usize,
    /// ALD hasher
    ald_hasher: Hasher,
    /// PLD hasher
    pld_hasher: Hasher,
    /// TLD hasher
    tld_hasher: Hasher,
    /// Finalized image?
    finalized: bool,
}

// Needs to be implemented manually as `CipherRef` and `Hasher` do not implement
// [`Debug`].
impl Debug for SecuredComponentBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecuredComponentBuilder")
            .field("chunk_size", &self.chunk_size)
            .field("cipher", &self.cipher.nid().long_name()?)
            .field("comp_key", &self.comp_key)
            .field("encrypt", &self.encrypt)
            .field("expert_mode", &self.expert_mode)
            .field("num_chunks", &self.num_chunks)
            .finish()
    }
}

impl SecuredComponentBuilder {
    /// Values used for the first (and current) Ultravisor implementation.
    const CHUNK_SIZE_V1: usize = 4096;
    const CIPHER_V1: SymKeyType = SymKeyType::Aes256Xts;
    pub const COMPONENT_ALIGNMENT_V1: u64 = 4096;
    const DIGEST_V1: Nid = Nid::SHA512;

    fn new(
        encrypt: bool,
        key_type: SymKeyType,
        digest_nid: Nid,
        chunk_size: usize,
    ) -> Result<Self> {
        let digest = MessageDigest::from_nid(digest_nid).ok_or(Error::UnsupportMessageDigest)?;
        let nid = key_type.into();
        let cipher = Cipher::from_nid(nid).ok_or(PvError::UnsupportedCipher(nid))?;
        let key = SymKey::random(key_type)?;

        Ok(Self {
            expert_mode: false,
            comp_key: key,
            cipher,
            encrypt,
            num_chunks: 0,
            chunk_size,
            ald_hasher: Hasher::new(digest)?,
            pld_hasher: Hasher::new(digest)?,
            tld_hasher: Hasher::new(digest)?,
            finalized: false,
        })
    }

    /// Creates a new [`Self`] that can be used for the preparation of V1
    /// secured components. AES256-XTS is used for the components encryption,
    /// SHA-512 for the ALD, PLD and TLD. The components must be aligned and a
    /// multiple of 4096 bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if the cipher or digest algorithm is
    /// not supported or no random key could be generated.
    pub fn new_v1(encryption: bool) -> Result<Self> {
        Self::new(
            encryption,
            Self::CIPHER_V1,
            Self::DIGEST_V1,
            Self::CHUNK_SIZE_V1,
        )
    }

    /// Activate the expert mode. For example, it's then allowed to change
    /// security related settings like setting the encryption keys manually.
    pub fn i_know_what_i_am_doing(&mut self) {
        self.expert_mode = true;
    }

    /// Sets the components key. This requires the expert mode to be active and
    /// there is also the restriction, that it cannot be changed after the first
    /// secured component was prepared.
    ///
    /// * `key_data` - Data that is used as the new components key.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * the expert mode is not active (see [`Self::i_know_what_i_am_doing`])
    /// * or a first component was already prepared or finalized
    /// * the key could not created by using `key_data`.
    pub fn set_components_key(&mut self, key_data: Confidential<Vec<u8>>) -> Result<()> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        // We have already encrypted a component, therefore reject the new
        // components key.
        if self.num_chunks > 0 || self.finalized {
            return Err(Error::FirstComponentAlreadyPrepared);
        }

        self.comp_key = SymKey::try_from_data(self.comp_key.key_type(), key_data)?;
        Ok(())
    }

    /// Prepare the given component and write it into the given writer and
    /// assume the given memory address.
    ///
    /// * `writer` - Write the prepared component into this writer.
    /// * `layout` - Memory layout where the prepared component is later used.
    /// * `component` - Component to be prepared as .
    /// * `addr` - Memory address where the prepared component later will later be located
    ///   (important for the Secure Execution header).
    /// * `tweak` - Tweak used for the component encryption.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * address is smaller than the expected next possible address.
    /// * the image was already finalized
    /// * the given tweak is invalid
    pub fn prepare_and_insert_as_secure_component<S, W: Write, T: ComponentTrait<S>>(
        &mut self,
        writer: &mut W,
        layout: &mut Layout,
        component: &mut T,
        addr: u64,
        tweak: Vec<u8>,
    ) -> Result<SecuredComponent> {
        let next_possible_addr = layout.next_addr;
        if addr < next_possible_addr {
            return Err(Error::NonMonotonicallyIncreasing {
                addr,
                next_addr: next_possible_addr,
            });
        }

        let alignment = layout.alignment;
        if (addr % alignment) != 0 {
            return Err(Error::UnalignedAddress { addr, alignment });
        }

        if alignment > self.chunk_size.try_into().unwrap() {
            return Err(Error::InvalidAlignment {
                alignment,
                chunk_size: self.chunk_size,
            });
        }

        let max_component_size = layout.max_size_of_chunk_at_addr(addr)?;
        let secured_comp = self.prepare_and_insert_as_secure_component_unchecked(
            writer,
            component,
            addr,
            max_component_size,
            tweak,
        )?;
        layout.insert_interval(secured_comp.src.start, secured_comp.src.size())?;
        Ok(secured_comp)
    }

    /// Prepare the given component and insert it at the given image address.
    ///
    /// * `writer` - Write the prepared component into this writer.
    /// * `component` - Component to be prepared.
    /// * `addr` - Address where the prepared component should be inserted.
    /// * `max_component_size`- Maximum possible size that the prepared component may have
    /// * `tweak` - Tweak used for the component encryption.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * address is smaller than the expected next possible address.
    /// * the image was already finalized
    /// * the given tweak is invalid
    fn prepare_and_insert_as_secure_component_unchecked<S, W: Write, T: ComponentTrait<S>>(
        &mut self,
        writer: &mut W,
        component: &mut T,
        addr: u64,
        max_component_size: Option<usize>,
        tweak: Vec<u8>,
    ) -> Result<SecuredComponent> {
        assert!(component.secure_mode());
        assert_ne!(self.chunk_size, 0);

        if self.finalized {
            return Err(Error::ImageAlreadyFinalized);
        }

        let expected_tweak_len = self.cipher.iv_length();
        if expected_tweak_len != tweak.len() {
            return Err(Error::InvalidTweakSize {
                given: tweak.len(),
                expected: expected_tweak_len,
            });
        }

        let mode = if self.encrypt && component.secure_mode() {
            Mode::Encrypt
        } else {
            Mode::Padding
        };

        let prepare_args = PrepareSecuredComponentArgs {
            addr,
            cipher: self.cipher,
            mode,
            key: self.comp_key.value(),
            iv: &tweak,
            chunk_size: self.chunk_size,
        };

        let mut ops = MetadataArgs {
            content_hasher: Some(&mut self.pld_hasher),
            tweak_hasher: Some(&mut self.tld_hasher),
            address_hasher: Some(&mut self.ald_hasher),
            num_chunks: Some(&mut self.num_chunks),
            max_component_size,
            input_size: 0,
            padded_input_size: 0,
            output_size: 0,
        };
        // Prepare the component and write the prepared data directly to the output
        prepare_component(&prepare_args, component, writer, Some(&mut ops))?;

        let original_size = ops.input_size;
        let prepared_size = ops.output_size.try_into()?;
        let src = Interval::new_with_size(addr, prepared_size)?;

        Ok(SecuredComponent {
            original_size,
            src: Rc::new(src),
            tweak_or_iv: tweak,
        })
    }

    /// Prepare the given component and append the prepared component to the
    /// back of the image layout.
    ///
    /// # Errors
    ///
    /// This function will return an error if the image was already finalized or
    /// the given tweak is invalid.
    pub fn prepare_and_append_as_secure_component<S, W: Write, T: ComponentTrait<S>>(
        &mut self,
        writer: &mut W,
        layout: &mut Layout,
        component: &mut T,
        tweak: Vec<u8>,
    ) -> Result<SecuredComponent> {
        let next_addr = layout.next_addr;
        self.prepare_and_insert_as_secure_component(writer, layout, component, next_addr, tweak)
    }

    /// Finalizes the image and returns the image metadata (the digests, number
    /// of chunks) and the key that was used for the components encryption.
    ///
    /// # Errors
    ///
    /// This function will return an error if the builder is already finalized
    /// or there was a problem in a cryptographic operation.
    pub fn finish(&mut self) -> Result<ComponentMetadata> {
        if self.finalized {
            return Err(Error::ImageAlreadyFinalized);
        }

        self.finalized = true;

        Ok(ComponentMetadata::ComponentMetadataV1(
            ComponentMetadataV1 {
                ald: try_copy_slice_to_array(self.ald_hasher.finish()?.as_ref())?,
                pld: try_copy_slice_to_array(self.pld_hasher.finish()?.as_ref())?,
                tld: try_copy_slice_to_array(self.tld_hasher.finish()?.as_ref())?,
                nep: self.num_chunks.try_into()?,
                key: try_copy_slice_to_array(self.comp_key.value())?.into(),
            },
        ))
    }

    /// Returns if encryption is used.
    pub const fn encryption_enabled(&self) -> bool {
        self.encrypt
    }

    /// Returns the chunk size.
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use std::{fmt::Debug, io::Cursor};

    use pv::request::Aes256XtsKey;

    use super::*;

    #[test]
    fn prepare_aligned_component_test() {
        #[derive(Debug)]
        struct TestComp<T: Read + Debug> {
            reader: T,
        }

        impl<T: Read + Debug> ComponentTrait<()> for TestComp<T> {
            fn secure_mode(&self) -> bool {
                true
            }

            fn kind(&self) {}
        }

        impl<T: Read + Debug> Read for TestComp<T> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reader.read(buf)
            }
        }

        let start_addr = 0x10000;
        let encryption = true;
        let mut writer = Cursor::new(Vec::new());
        let mut ctx = SecuredComponentBuilder::new_v1(encryption).expect("should work");
        let mut key = vec![0x42; 32];
        key.extend([0x43; 32]);
        ctx.i_know_what_i_am_doing();
        ctx.set_components_key(
            Aes256XtsKey::new(<[u8; 64]>::try_from(key.as_slice()).unwrap()).into(),
        )
        .unwrap();
        let input_data1 = vec![0x1; 0x3400];
        let input_data2 = vec![0x2; 0x3000];

        let mut comp1 = TestComp {
            reader: Cursor::new(input_data1),
        };
        let tweak1 = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        let img_comp_res = ctx.prepare_and_insert_as_secure_component_unchecked(
            &mut writer,
            &mut comp1,
            start_addr,
            None,
            tweak1,
        );
        assert!(img_comp_res.is_ok());
        assert_eq!(ctx.num_chunks, 4);

        let reader2 = Cursor::new(input_data2);
        let mut comp2 = TestComp { reader: reader2 };
        let tweak2 = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let img_comp_res = ctx.prepare_and_insert_as_secure_component_unchecked(
            &mut writer,
            &mut comp2,
            0x20000,
            None,
            tweak2,
        );
        assert!(img_comp_res.is_ok());
        assert_eq!(ctx.num_chunks, 7);

        let metav1: ComponentMetadataV1 = ctx
            .finish()
            .expect("should not fail")
            .try_into()
            .expect("should not fail");

        // Check ALD
        assert_eq!(
            metav1.ald,
            [
                195, 145, 222, 87, 39, 160, 130, 18, 234, 47, 234, 156, 55, 249, 207, 9, 11, 229,
                31, 147, 198, 213, 33, 184, 144, 99, 50, 206, 114, 12, 95, 56, 173, 160, 231, 62,
                105, 102, 62, 82, 17, 208, 21, 254, 244, 29, 198, 38, 6, 245, 19, 94, 97, 153, 4,
                212, 244, 80, 171, 136, 159, 73, 202, 173
            ],
        );

        // Check PLD
        assert_eq!(
            metav1.pld,
            [
                162, 79, 243, 10, 138, 241, 41, 88, 136, 222, 223, 233, 54, 158, 181, 9, 41, 3, 9,
                169, 1, 89, 235, 195, 44, 162, 106, 83, 249, 212, 54, 74, 120, 24, 87, 226, 89, 5,
                135, 83, 108, 62, 118, 115, 85, 199, 183, 96, 63, 43, 12, 106, 64, 127, 22, 51, 13,
                130, 18, 141, 9, 100, 250, 210
            ]
        );

        // Check TLD
        let digest = MessageDigest::sha512();
        let mut hasher_new = Hasher::new(digest).expect("should work");
        // Tweaks for comp1
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 0])
            .expect("should work");
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 16, 0])
            .expect("should work");
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 32, 0])
            .expect("should work");
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 48, 0])
            .expect("should work");

        // Tweaks for comp2
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 0])
            .expect("should work");
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 16, 0])
            .expect("should work");
        hasher_new
            .update(&[0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 32, 0])
            .expect("should work");
        let exp = hasher_new.finish().expect("should work");

        assert_eq!(metav1.tld, *exp);
        assert_eq!(
            metav1.tld,
            [
                66, 79, 227, 207, 4, 166, 246, 74, 122, 239, 24, 92, 59, 78, 246, 7, 192, 228, 245,
                75, 183, 225, 70, 32, 181, 116, 163, 211, 30, 239, 49, 199, 212, 98, 235, 4, 13,
                69, 238, 105, 24, 230, 184, 9, 104, 186, 68, 84, 249, 226, 237, 194, 111, 105, 41,
                237, 98, 77, 0, 85, 242, 53, 86, 89
            ]
        );
    }

    #[test]
    fn test_update_ald_digest() {
        let start = 0x10000;
        let stop = 0x13400;
        let digest = MessageDigest::sha512();
        let mut hasher = Hasher::new(digest).expect("should work");
        let mut hasher_new = Hasher::new(digest).expect("should work");

        hasher_new
            .update(&0x10000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x11000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x12000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x13000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x20000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x21000_u64.to_be_bytes())
            .expect("should work");
        hasher_new
            .update(&0x22000_u64.to_be_bytes())
            .expect("should work");
        let exp = hasher_new.finish().expect("should work");

        let chunks_count_res = update_ald_digest(&mut hasher, &Interval { start, stop }, 4096);
        assert!(chunks_count_res.is_ok());
        assert_eq!(chunks_count_res.unwrap(), 4);

        let chunks_count_res = update_ald_digest(
            &mut hasher,
            &Interval {
                start: 0x20000,
                stop: 0x23000,
            },
            4096,
        );
        assert!(chunks_count_res.is_ok());
        assert_eq!(chunks_count_res.unwrap(), 3);

        let res_ret = hasher.finish();
        assert!(res_ret.is_ok());
        let res = res_ret.unwrap();
        assert_eq!(&*exp, &*res,);
        assert_eq!(
            &*res,
            [
                195, 145, 222, 87, 39, 160, 130, 18, 234, 47, 234, 156, 55, 249, 207, 9, 11, 229,
                31, 147, 198, 213, 33, 184, 144, 99, 50, 206, 114, 12, 95, 56, 173, 160, 231, 62,
                105, 102, 62, 82, 17, 208, 21, 254, 244, 29, 198, 38, 6, 245, 19, 94, 97, 153, 4,
                212, 244, 80, 171, 136, 159, 73, 202, 173
            ]
        );
    }
}

// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{
    fmt::Display,
    io::{Cursor, Seek, SeekFrom, Write},
    path::PathBuf,
    rc::Rc,
};

use anyhow::{anyhow, Context, Result};
use deku::DekuContainerRead;
use log::debug;
use openssl::pkey::{PKey, Public};
use pv::{misc::read_file, request::Confidential};
use pvimg::{
    error::Error,
    misc::{round_up, serialize_to_bytes, ShortPsw, PSW, PSW_MASK_BA, PSW_MASK_EA},
    secured_comp::{ComponentTrait, Interval, Layout, SecuredComponent, SecuredComponentBuilder},
    uvdata::{
        BuilderTrait, PlaintextControlFlagsV1, SeHdrBuilder, SeHdrVersion, SecretControlFlagsV1,
    },
};

use crate::se_img_comps::{
    create_ipib, ipib::Ipib, kernel::S390Kernel, metadata::ImgMetaData, render_stage3a,
    render_stage3b, sehdr::SeHdrComp, shortpsw::ShortPSWComp, stage3a_path, stage3b_path,
    CompTweakV1, Component, ComponentKind, STAGE3A_ENTRY, STAGE3A_INIT_ENTRY, STAGE3A_LOAD_ADDRESS,
};

pub struct SeHdrArgs<'a> {
    pub keys: &'a [PKey<Public>],
    pub pcf: &'a PlaintextControlFlagsV1,
    pub scf: &'a SecretControlFlagsV1,
    pub cck: &'a Option<(PathBuf, Confidential<Vec<u8>>)>,
    pub hdr_aead_key: &'a Option<(PathBuf, Confidential<Vec<u8>>)>,
    pub psw_addr: &'a Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImgComponent {
    kind: ComponentKind,
    pub(crate) src: Rc<Interval>,
    pub(crate) secure_mode: Option<SecuredComponent>,
}

impl ImgComponent {
    pub fn kind(&self) -> ComponentKind {
        self.kind.clone()
    }
}

impl Ord for ImgComponent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.src.cmp(&other.src)
    }
}

impl PartialOrd for ImgComponent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for ImgComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "| {:23} | ", self.kind.to_string())?;
        self.src.to_string().fmt(f)?;
        write!(f, " |")
    }
}

pub struct SeImgBuilder<W> {
    /// Expert mode (components encryption key and Secure Execution header
    /// protection key can be set). By default disabled.
    expert_mode: bool,
    writer: W,
    layout: Layout,
    comps: Vec<Rc<ImgComponent>>,
    builder: SecuredComponentBuilder,
    stage3a: Vec<u8>,
    stage3b: Vec<u8>,
    /// The legacy Secure Execution header address (directly after stage3a)
    legacy_se_hdr_addr: Option<u64>,
    finalized: bool,
}

impl<W: Write + Seek> SeImgBuilder<W> {
    const COMPONENT_ALIGNMENT_V1: u64 = SecuredComponentBuilder::COMPONENT_ALIGNMENT_V1;
    const DEFAULT_INITIAL_PSW_MASK: u64 = PSW_MASK_BA | PSW_MASK_EA;

    /// Create a Secure Execution boot image builder
    #[allow(clippy::similar_names)]
    pub(crate) fn new_v1(
        mut writer: W,
        encryption: bool,
        legacy_expected_se_hdr_size: Option<usize>,
        bootloader_dir: Option<&PathBuf>,
    ) -> Result<Self> {
        let stage3a = read_file(stage3a_path(bootloader_dir), "stage3a")?;
        let stage3b = read_file(stage3b_path(bootloader_dir), "stage3b")?;
        let mut legacy_se_hdr_addr = None;

        // Reserve memory space for the stage3a loader that will be written
        // later.
        let mut next_comp_addr: u64 = round_up(
            STAGE3A_LOAD_ADDRESS
                .checked_add(stage3a.len().try_into()?)
                .ok_or(Error::UnexpectedOverflow)?,
            Self::COMPONENT_ALIGNMENT_V1,
        )?;

        // Reserve memory space for the Secure Execution header in case of
        // legacy mode.
        if let Some(expected_se_hdr_size) = legacy_expected_se_hdr_size {
            // Place the Secure Execution header next to the stage3a and use as
            // the minimum address 0x14000. 0x14000 is used as the starting
            // point for searching the Secure Execution header in the
            // `pvextract-hdr` utility and we can therefore not use e.g. 0x13000
            // even if it would be possible in regard to the memory layout.
            const PV_EXTRACT_SE_HDR_SEARCH_ADDR: u64 = 0x14000;
            let se_hdr_addr = std::cmp::max(next_comp_addr, PV_EXTRACT_SE_HDR_SEARCH_ADDR);
            next_comp_addr = round_up(
                se_hdr_addr
                    .checked_add(expected_se_hdr_size.try_into()?)
                    .ok_or(Error::UnexpectedOverflow)?,
                Self::COMPONENT_ALIGNMENT_V1,
            )?;
            legacy_se_hdr_addr = Some(se_hdr_addr);
        }

        if next_comp_addr % Self::COMPONENT_ALIGNMENT_V1 != 0 {
            return Err(Error::UnalignedAddress {
                addr: next_comp_addr,
                alignment: Self::COMPONENT_ALIGNMENT_V1,
            }
            .into());
        }

        // Secure Execution expects, that the component addresses are aligned to
        // 4096.
        let layout = Layout::new(next_comp_addr, Self::COMPONENT_ALIGNMENT_V1)?;
        let builder = SecuredComponentBuilder::new_v1(encryption)?;

        // The layout of the boot image matches with the memory layout as it
        // it's loaded at location 0x0. Therefore let's seek to the
        // `next_comp_addr`.
        writer.seek(SeekFrom::Start(next_comp_addr))?;

        Ok(Self {
            layout,
            expert_mode: false,
            comps: vec![],
            writer,
            builder,
            legacy_se_hdr_addr,
            stage3a,
            stage3b,
            finalized: false,
        })
    }

    /// Enable expert mode - this is required for specifying component tweaks by
    /// hand etc...
    pub(crate) fn i_know_what_i_am_doing(&mut self) {
        self.builder.i_know_what_i_am_doing();
        self.expert_mode = true;
    }

    /// Prepare the given component as secured component, append it to the layout
    /// and write it to the output.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///  + stage3b has already been added
    ///  + problem with the preparation of the secured component
    ///  + serialization problem of the component tweak (very unlikely)
    ///  + a tweak was given, but the expert mode not enabled
    pub(crate) fn prepare_and_append_as_secure_component<T>(
        &mut self,
        component: &mut T,
        tweak: Option<Vec<u8>>,
    ) -> Result<Rc<ImgComponent>>
    where
        T: ComponentTrait<ComponentKind>,
    {
        if self.finalized {
            return Err(Error::ImgAlreadyFinalized.into());
        }

        if !component.secure_mode() {
            unreachable!("Bug")
        }

        if tweak.is_some() && !self.expert_mode {
            return Err(Error::NonExpertModeTweakGiven.into());
        }

        debug!("Preparing {} as secured component", component.kind());
        let tweak = tweak.unwrap_or(serialize_to_bytes(&CompTweakV1::new(component.kind())?)?);
        // No reason to seek as there are no holes between components (addr
        // alignment == alignment of the component size). If that changes we have to seek beforehand
        // to `self.layout.next_addr` self.writer.seek(SeekFrom::Start(self.layout.
        // next_addr))?;

        let secured_comp = self.builder.prepare_and_append_as_secure_component(
            &mut self.writer,
            &mut self.layout,
            component,
            tweak,
        )?;

        let img_comp = Rc::new(ImgComponent {
            kind: component.kind(),
            src: secured_comp.src.clone(),
            secure_mode: Some(secured_comp),
        });
        self.comps.push(img_comp.clone());
        Ok(img_comp)
    }

    /// Insert and write the given non-secured component at the given address.
    fn insert_nonsecure_component<T: ComponentTrait<ComponentKind>>(
        &mut self,
        component: &mut T,
        addr: u64,
    ) -> Result<Rc<ImgComponent>> {
        // FIXME Guarantee this during compile time using a "SecureMode" trait.
        if component.secure_mode() {
            unreachable!("Programming bug!")
        };

        let max_component_size = self.layout.max_size_of_chunk_at_addr(addr)?;
        let mut buf = vec![0_u8; self.builder.chunk_size()];
        let mut total_written_count: usize = 0;

        assert_ne!(buf.len(), 0);

        self.writer.seek(SeekFrom::Start(addr))?;
        loop {
            let read_count = component.read(&mut buf)?;
            // The end of file has reached as it's guaranteed that the buffer
            // [`buf`] has a length != 0. See
            // https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
            if read_count == 0 {
                break;
            }

            if let Some(max_component_size) = max_component_size {
                if total_written_count
                    .checked_add(read_count)
                    .ok_or(Error::UnexpectedOverflow)?
                    > max_component_size
                {
                    return Err(anyhow!(
                        "BUG: Component is too large for this location in the image: {} > {}",
                        total_written_count + read_count,
                        max_component_size
                    ));
                }
            }

            self.writer.write_all(&buf[0..read_count])?;
            total_written_count = total_written_count
                .checked_add(read_count)
                .ok_or(Error::UnexpectedOverflow)?;
        }

        let src = self
            .layout
            .insert_interval(addr, total_written_count.try_into()?)?;
        let img_comp = Rc::new(ImgComponent {
            src,
            kind: component.kind(),
            secure_mode: None,
        });

        match self.comps.binary_search(&img_comp) {
            Ok(_pos) => {
                return Err(anyhow!(
                    "BUG: There is already another component at this location"
                ))
            }
            Err(pos) => self.comps.insert(pos, img_comp.clone()),
        }
        Ok(img_comp)
    }

    fn append_component<T: ComponentTrait<ComponentKind>>(
        &mut self,
        component: &mut T,
    ) -> Result<Rc<ImgComponent>> {
        let next_addr = self.layout.next_addr;
        self.insert_nonsecure_component(component, next_addr)
    }

    /// Prepare IPIB and write it to file
    fn add_ipib(&mut self, sehdr_src: &Interval) -> Result<Rc<ImgComponent>> {
        let img_comps_tweak_and_src: Result<Vec<_>> = self
            .comps
            .iter()
            .filter(|comp| comp.secure_mode.is_some())
            .map(|comp| {
                // Safety: We checked in the filter for `comp.secure_mode.is_some()`.
                let secure_mode_data = comp.secure_mode.as_ref().unwrap();
                let src = &comp.src;
                let (_, tweak) = CompTweakV1::from_bytes((secure_mode_data.tweak(), 0))?;
                Ok((tweak.pref, src.clone()))
            })
            .collect();
        let ipib = create_ipib(sehdr_src, img_comps_tweak_and_src?)?;
        let mut ipib_comp = Ipib::new(Box::new(Cursor::new(serialize_to_bytes(&ipib)?)));
        self.append_component(&mut ipib_comp)
    }

    /// Prepare Secure Execution header and write it to the output
    fn add_sehdr(&mut self, stage3b_entry: u64, sehdr_args: SeHdrArgs) -> Result<Rc<ImgComponent>> {
        let meta = self.builder.finish()?;

        let mut se_hdr_builder = SeHdrBuilder::new(
            SeHdrVersion::V1,
            PSW {
                addr: sehdr_args.psw_addr.unwrap_or(stage3b_entry),
                mask: Self::DEFAULT_INITIAL_PSW_MASK,
            },
            meta,
        )?;
        se_hdr_builder
            .add_hostkeys(sehdr_args.keys)?
            .with_pcf(sehdr_args.pcf)?
            .with_scf(sehdr_args.scf)?;

        if self.expert_mode {
            se_hdr_builder.i_know_what_i_am_doing();
        }

        if let Some((path, cck)) = &sehdr_args.cck {
            se_hdr_builder
                .with_cck(cck.clone())
                .with_context(|| format!("Failed to use '{}' as the CCK", path.display()))?;
        }

        if let Some((path, prot_key)) = sehdr_args.hdr_aead_key {
            se_hdr_builder
                .with_aead_key(prot_key.clone())
                .with_context(|| {
                    format!(
                        "Failed to use '{}' as the Secure Execution header protection key",
                        path.display()
                    )
                })?;
        }

        let se_hdr_bin = se_hdr_builder.build()?;
        let mut comp: Component =
            SeHdrComp::new(Box::new(Cursor::new(se_hdr_bin.as_bytes()?))).into();

        if let Some(se_hdr_addr) = self.legacy_se_hdr_addr {
            self.insert_nonsecure_component(&mut comp, se_hdr_addr)
        } else {
            self.append_component(&mut comp)
        }
    }

    /// Finish the Secure Execution image - e.g. create Stage3a, Stage3b, Secure
    /// Execution header and so on.
    #[allow(clippy::similar_names)]
    pub fn finish(mut self, sehdr_args: SeHdrArgs) -> Result<Vec<Rc<ImgComponent>>> {
        if (sehdr_args.hdr_aead_key.is_some() || sehdr_args.psw_addr.is_some()) && !self.expert_mode
        {
            return Err(Error::NonExpertMode.into());
        }

        // Create stage3b and write it to the output file
        let psw = PSW {
            addr: S390Kernel::KERNEL_ENTRY,
            mask: Self::DEFAULT_INITIAL_PSW_MASK,
        };
        let stage3b_img_comp = self
            .add_stage3b(psw)
            .context("Failed to prepare stage3b component")?;

        // Create Secure Execution header and write it to the output file
        let sehdr_img_comp = self
            .add_sehdr(stage3b_img_comp.src.start, sehdr_args)
            .context("Failed to prepare Secure Execution header")?;

        // Create and write IPIB to the output file
        let ipib_img_comp = self
            .add_ipib(&sehdr_img_comp.src)
            .context("Failed to prepare IPIB")?;

        // Create and write stage3a to the output file
        let stage3a_img_comp = self
            .add_stage3a(&sehdr_img_comp.src, &ipib_img_comp.src)
            .context("Failed to prepare Stage3a")?;
        assert_eq!(stage3a_img_comp.src.start, STAGE3A_INIT_ENTRY);
        assert_eq!(stage3a_img_comp.src.start + 0x1000, STAGE3A_ENTRY);

        // Create and write short PSW at the beginning of the file
        let _short_psw_img_comp = self.add_short_psw(
            stage3a_img_comp
                .src
                .start
                .checked_add(0x1000)
                .ok_or(Error::UnexpectedOverflow)?,
        )?;

        // Create and write Secure Execution boot image meta data right after the short PSW
        let _metadata_img_comp =
            self.add_metadata(ipib_img_comp.src.start, sehdr_img_comp.src.start)?;

        Ok(self.comps)
    }

    /// Prepare stage3a and write it to file
    fn add_stage3a(
        &mut self,
        se_hdr_src: &Interval,
        ipib_src: &Interval,
    ) -> Result<Rc<ImgComponent>> {
        let stage3a_load_addr = STAGE3A_LOAD_ADDRESS;
        let mut stage3a_comp = render_stage3a(
            self.stage3a.clone(),
            stage3a_load_addr,
            se_hdr_src,
            ipib_src,
        )?;
        self.insert_nonsecure_component(&mut stage3a_comp, stage3a_load_addr)
    }

    /// Prepare short PSW and write it to file
    fn add_short_psw(&mut self, stage3a_entry: u64) -> Result<Rc<ImgComponent>> {
        let short_psw: ShortPsw = PSW {
            addr: stage3a_entry,
            mask: Self::DEFAULT_INITIAL_PSW_MASK,
        }
        .try_into()?;

        let mut short_psw_comp =
            ShortPSWComp::new(Box::new(Cursor::new(serialize_to_bytes(&short_psw)?)));
        self.insert_nonsecure_component(&mut short_psw_comp, ShortPSWComp::OFFSET)
    }

    /// Prepare Secure Execution image metadata and write it to the file
    fn add_metadata(&mut self, ipib_off: u64, hdr_off: u64) -> Result<Rc<ImgComponent>> {
        let mut metadata_comp = ImgMetaData::new(ipib_off, hdr_off)?;

        let metadata_img_comp =
            self.insert_nonsecure_component(&mut metadata_comp, ImgMetaData::OFFSET)?;
        if metadata_img_comp.src.size() > ImgMetaData::MAX_SIZE {
            unreachable!("The metadata should never be larger than the BSS size of stage3a");
        }
        Ok(metadata_img_comp)
    }

    /// Prepare stage3b and write it to file
    fn add_stage3b(&mut self, psw: PSW) -> Result<Rc<ImgComponent>> {
        // Prepare stage3b - for this we must prepare the arguments for it. Since we
        // have the memory layout for the movable components (kernel, cmdline, and
        // initrd) we can do this now.
        let mut stage3b_comp = render_stage3b(self.stage3b.clone(), psw, &self.comps)?;

        let result = self.prepare_and_append_as_secure_component(&mut stage3b_comp, None);
        // No other "regular components can be added now
        self.finalized = true;
        result
    }

    pub(crate) fn set_components_key(
        &mut self,
        key_data: Confidential<Vec<u8>>,
    ) -> pvimg::error::Result<()> {
        self.builder.set_components_key(key_data)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::SeImgBuilder;
    use crate::{se_img::stage3a_path, se_img_comps::stage3b_path};

    #[test]
    fn test_comp_ctx_new() {
        // If the bootloader does not exist, we cannot test.
        if !stage3a_path(None).exists() || !stage3b_path(None).exists() {
            return;
        }

        let encryption = true;
        let mut writer = Cursor::new(Vec::new());
        let ctx_res = SeImgBuilder::new_v1(&mut writer, encryption, None, None);
        assert!(ctx_res.is_ok());
        let ctx = ctx_res.unwrap();

        assert_eq!(ctx.layout.next_addr, 0x13000);
        assert!(ctx.builder.encryption_enabled());
        assert_eq!(ctx.comps, vec![]);
    }
}

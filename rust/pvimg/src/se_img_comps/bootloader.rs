// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{io::Cursor, path::PathBuf, rc::Rc};

pub mod ipl;
mod stage3a_defs;
mod stage3b_defs;
use ipl::IPL_PARM_BLOCK_PV_VERSION;
use log::trace;
use pvimg::{
    error::{Error, Result},
    misc::{serialize_to_bytes, PSW},
    secured_comp::Interval,
};

pub use self::stage3a_defs::{STAGE3A_ENTRY, STAGE3A_INIT_ENTRY, STAGE3A_LOAD_ADDRESS};
use self::{
    ipl::{
        ipl_parameter_block, ipl_pb0_pv, ipl_pb0_pv_comp, ipl_pbt_IPL_PBT_PV, ipl_pl_hdr,
        IPL_PARM_BLOCK_VERSION,
    },
    stage3b_defs::{memblob, stage3b_args},
};
use super::CompTweakPrefV1;
use crate::{
    se_img::ImgComponent,
    se_img_comps::{
        bootloader::stage3a_defs::stage3a_args, stage3a::Stage3a, stage3b::Stage3b, ComponentKind,
    },
};

/// Get the `PVIMG_PKGDATADIR` used for `pvimg`
///
/// Provides the package data directory for `pvimg`.
/// For release builds this requires the environment variable
/// `PVIMG_PKGDATADIR` to be present at compile time.
/// For debug builds this value defaults to `CARGO_MANIFEST_DIR/boot/`
/// if that variable is not present.
/// Should only be used by binary targets!!
///
/// Collapses to a compile time constant, that is likely to be inlined by the
/// compiler in release builds.
macro_rules! pvimg_pkg_data {
    () => {{
     #[cfg(debug_assertions)]
    match option_env!("PVIMG_PKGDATADIR") {
        Some(data) => data,
        None => concat!(env!("CARGO_MANIFEST_DIR"), "/boot/"),
    }
    #[cfg(not(debug_assertions))]
    env!("PVIMG_PKGDATADIR", "env 'PVIMG_PKGDATADIR' must be set for release builds. Trigger build using the s390-tools build system or export the variable yourself")
    }};
}

fn bootloader_dir(path: Option<&PathBuf>) -> PathBuf {
    path.map_or_else(|| PathBuf::from(pvimg_pkg_data!()), |v| v.to_owned())
}

/// Returns the path to `stage3a.bin`.
pub fn stage3a_path(dir: Option<&PathBuf>) -> PathBuf {
    bootloader_dir(dir).join("stage3a.bin")
}

/// Returns the path to `stage3b_reloc.bin`.
pub fn stage3b_path(dir: Option<&PathBuf>) -> PathBuf {
    bootloader_dir(dir).join("stage3b_reloc.bin")
}

/// Render stage3b "template"
pub fn render_stage3a(
    mut stage3a: Vec<u8>,
    stage3a_addr: u64,
    se_hdr_src: &Interval,
    ipib_src: &Interval,
) -> Result<Stage3a> {
    let stage3a_size = stage3a.len();
    let stage3a_size_u64: u64 = stage3a_size.try_into()?;

    if stage3a_size < 24 {
        unreachable!("Bug!");
    }
    let stage3a_data_addr = stage3a_addr
        .checked_add(stage3a_size_u64)
        .ok_or(Error::UnexpectedOverflow)?
        - 24;
    assert!(
        se_hdr_src.start
            > stage3a_addr
                .checked_add(stage3a_size_u64)
                .ok_or(Error::UnexpectedOverflow)?
    );
    // IMPORTANT: Secure Execution header must be located AFTER the stage3a
    // loader.
    let hdr_offs = se_hdr_src
        .start
        .checked_sub(stage3a_data_addr)
        .ok_or(Error::UnexpectedUnderflow)?;
    assert!(
        ipib_src.start
            > stage3a_addr
                .checked_add(stage3a_size_u64)
                .ok_or(Error::UnexpectedOverflow)?
    );
    // IMPORTANT: IPIB must be located AFTER the stage3a loader.
    let ipib_offs = ipib_src
        .start
        .checked_sub(stage3a_data_addr)
        .ok_or(Error::UnexpectedUnderflow)?;
    let args = stage3a_args {
        hdr_offs,
        hdr_size: se_hdr_src.size(),
        ipib_offs,
    };

    trace!("stage3a arguments: {args:#x?}");

    let stage3a_args_bin = serialize_to_bytes(&args)?;
    assert_eq!(stage3a_args_bin.len(), 24);

    // Insert the stage3a arguments
    assert!(stage3a_size > stage3a_args_bin.len());
    stage3a.splice(stage3a_size - stage3a_args_bin.len().., stage3a_args_bin);
    Ok(Stage3a::new(Box::new(Cursor::new(stage3a))))
}

/// Render stage3b "template"
pub fn render_stage3b(
    mut stage3b: Vec<u8>,
    psw: PSW,
    prepared_comps: &[Rc<ImgComponent>],
) -> Result<Stage3b> {
    let mut args = stage3b_args {
        psw,
        ..Default::default()
    };
    prepared_comps
        .iter()
        .filter(|comp| comp.secure_mode.is_some() && comp.kind() != ComponentKind::Stage3b)
        .map(|comp| {
            // Safety: Safe because of the filtering.
            let secure_mode_data = comp.secure_mode.as_ref().unwrap();
            let src = comp.src.start;
            let size = secure_mode_data.original_size.try_into()?;
            match comp.kind() {
                ComponentKind::Cmdline => args.cmdline = memblob { src, size },
                ComponentKind::Kernel => args.kernel = memblob { src, size },
                ComponentKind::Ramdisk => args.initrd = memblob { src, size },
                ComponentKind::Stage3a
                | ComponentKind::Ipib
                | ComponentKind::SeHdr
                | ComponentKind::ShortPSW
                | ComponentKind::Stage3b => unreachable!(),
            }
            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;

    if prepared_comps.len() > 3 {
        // That would mean there is a bug somewhere.
        unreachable!()
    }

    trace!("stage3b arguments: {args:#x?}");

    let stage3b_args_bin = serialize_to_bytes(&args)?;
    assert_eq!(stage3b_args_bin.len(), 64);

    let stage3b_len = stage3b.len();
    let stage3b_args_bin_len = stage3b_args_bin.len();

    // Insert the stage3b arguments
    assert!(stage3b_len > stage3b_args_bin_len);
    let stage3b_parms_off = stage3b_len - stage3b_args_bin_len;
    stage3b.splice(stage3b_parms_off.., stage3b_args_bin);

    Ok(Stage3b::new(Box::new(Cursor::new(stage3b))))
}

pub fn create_ipib(
    hdr: &Interval,
    img_comps: Vec<(CompTweakPrefV1, Rc<Interval>)>,
) -> Result<ipl_parameter_block> {
    let mut components = vec![];
    for (tweak_pref, src) in img_comps {
        components.push(ipl_pb0_pv_comp {
            tweak_pref: tweak_pref.to_u64(),
            addr: src.start,
            len: src.size(),
        });
    }

    let comps_len = components.len();
    let ipip_len = ipl_parameter_block::size(comps_len)?.try_into()?;
    let ipip_pv_len = ipl_pb0_pv::size(comps_len)?.try_into()?;
    let ipib = ipl_parameter_block {
        hdr: ipl_pl_hdr {
            len: ipip_len,
            flags: 0,
            version: IPL_PARM_BLOCK_VERSION,
            ..Default::default()
        },
        pv: ipl_pb0_pv {
            len: ipip_pv_len,
            pbt: ipl_pbt_IPL_PBT_PV,
            version: IPL_PARM_BLOCK_PV_VERSION,
            num_comp: comps_len.try_into()?,
            pv_hdr_addr: hdr.start,
            pv_hdr_size: hdr.size(),
            components,
            ..Default::default()
        },
    };
    Ok(ipib)
}

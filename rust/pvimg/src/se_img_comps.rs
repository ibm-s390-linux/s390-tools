// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{
    fmt::{Debug, Display},
    io::{Read, Seek, SeekFrom},
};

use anyhow::Context;
use deku::{ctx::Endian, DekuRead, DekuWrite};
use enum_dispatch::enum_dispatch;
use pv::request::random_array;
use pvimg::{error::Result, secured_comp::ComponentTrait};

use self::{
    cmdline::Cmdline, kernel::S390Kernel, ramdisk::Ramdisk, sehdr::SeHdrComp,
    shortpsw::ShortPSWComp, stage3a::Stage3a, stage3b::Stage3b,
};
pub use crate::se_img_comps::bootloader::{
    create_ipib, render_stage3a, render_stage3b, stage3a_path, stage3b_path, STAGE3A_ENTRY,
    STAGE3A_INIT_ENTRY, STAGE3A_LOAD_ADDRESS,
};
use crate::se_img_comps::ipib::Ipib;

mod bootloader;

pub mod cmdline;
pub mod ipib;
pub mod kernel;
pub mod ramdisk;
pub mod sehdr;
pub mod shortpsw;
pub mod stage3a;
pub mod stage3b;

/// A trait for checking a component.
#[enum_dispatch]
trait ComponentCheckTrait: ComponentTrait<ComponentKind> {
    /// Check the component
    ///
    /// Note: The implementer does not have to care about resetting the file position
    ///       as this is done by [`ComponentCheckCtx`].
    fn check(&mut self, ctx: &ComponentCheckCtx) -> Result<()>;

    /// Initialize [`ComponentCheckCtx`], e.g. it reads what max kernel command
    /// line is supported by the given Linux kernel.
    ///
    /// Note: The implementer does not have to care about resetting the file
    ///       position as this is done by the [`ComponentCheckCtx`]
    fn init_ctx(&mut self, ctx: &mut ComponentCheckCtx) -> Result<()>;
}

#[derive(Debug)]
struct ComponentCheckCtx {
    max_kernel_cmdline_size: usize,
}

impl Default for ComponentCheckCtx {
    fn default() -> Self {
        Self {
            max_kernel_cmdline_size: S390Kernel::LEGACY_MAX_COMMAND_LINE_SIZE,
        }
    }
}

impl ComponentCheckCtx {
    fn new() -> Self {
        Default::default()
    }

    // Initialize component context.
    fn init(&mut self, component: &mut Component) -> Result<()> {
        let old_pos = component.stream_position()?;
        let result = component.init_ctx(self);
        component.seek(SeekFrom::Start(old_pos))?;
        result
    }

    // Check component.
    fn check_comp(&self, component: &mut Component) -> Result<()> {
        let old_pos = component.stream_position()?;
        let result = component.check(self);
        component.seek(SeekFrom::Start(old_pos))?;
        result
    }
}

/// Check the given components.
///
/// The original stream position of the components remains as it was before
/// calling this function.
///
/// # Errors
///
/// This function will return an error if there was an IO error or the component
/// check has failed.
pub fn check_components(components: &mut [Component]) -> Result<(), anyhow::Error> {
    let mut components_ctx = ComponentCheckCtx::new();
    for component in components.iter_mut() {
        components_ctx
            .init(component)
            .with_context(|| format!("Check for {} component has failed", component.kind()))?;
    }
    for component in components.iter_mut() {
        components_ctx
            .check_comp(component)
            .with_context(|| format!("Check for {} component has failed", component.kind()))?;
    }
    Ok(())
}

#[non_exhaustive]
#[derive(Debug)]
#[enum_dispatch(ComponentCheckTrait)]
pub enum Component {
    ShortPSW(ShortPSWComp),
    Stage3a(Stage3a),
    Kernel(S390Kernel),
    Ramdisk(Ramdisk),
    Cmdline(Cmdline),
    Stage3b(Stage3b),
    SeHdr(SeHdrComp),
    Ipib(Ipib),
}

// No `enum_dispatch` can be used since the trait is implemented in another
// crate.
impl Seek for Component {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::ShortPSW(obj) => obj.seek(pos),
            Self::Stage3a(obj) => obj.seek(pos),
            Self::Kernel(obj) => obj.seek(pos),
            Self::Ramdisk(obj) => obj.seek(pos),
            Self::Cmdline(obj) => obj.seek(pos),
            Self::Stage3b(obj) => obj.seek(pos),
            Self::SeHdr(obj) => obj.seek(pos),
            Self::Ipib(obj) => obj.seek(pos),
        }
    }
}

// No `enum_dispatch` can be used since the trait is implemented in another
// crate.
impl Read for Component {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::ShortPSW(obj) => obj.read(buf),
            Self::Stage3a(obj) => obj.read(buf),
            Self::Kernel(obj) => obj.read(buf),
            Self::Ramdisk(obj) => obj.read(buf),
            Self::Cmdline(obj) => obj.read(buf),
            Self::Stage3b(obj) => obj.read(buf),
            Self::SeHdr(obj) => obj.read(buf),
            Self::Ipib(obj) => obj.read(buf),
        }
    }
}

// No `enum_dispatch` can be used since the trait is implemented in another
// crate.
impl ComponentTrait<ComponentKind> for Component {
    fn secure_mode(&self) -> bool {
        match self {
            Self::ShortPSW(obj) => obj.secure_mode(),
            Self::Stage3a(obj) => obj.secure_mode(),
            Self::Kernel(obj) => obj.secure_mode(),
            Self::Ramdisk(obj) => obj.secure_mode(),
            Self::Cmdline(obj) => obj.secure_mode(),
            Self::Stage3b(obj) => obj.secure_mode(),
            Self::SeHdr(obj) => obj.secure_mode(),
            Self::Ipib(obj) => obj.secure_mode(),
        }
    }

    fn kind(&self) -> ComponentKind {
        match self {
            Self::ShortPSW(obj) => obj.kind(),
            Self::Stage3a(obj) => obj.kind(),
            Self::Kernel(obj) => obj.kind(),
            Self::Ramdisk(obj) => obj.kind(),
            Self::Cmdline(obj) => obj.kind(),
            Self::Stage3b(obj) => obj.kind(),
            Self::SeHdr(obj) => obj.kind(),
            Self::Ipib(obj) => obj.kind(),
        }
    }
}

// Trick to be able to pass it as `&dyn ReadSeekDebug`
pub trait ReadSeekDebug: Read + Seek + Debug {}
impl<T: Read + Seek + Debug> ReadSeekDebug for T {}

#[derive(Debug)]
pub struct CompReader {
    reader: Box<dyn ReadSeekDebug>,
}

impl CompReader {
    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self { reader }
    }
}

impl Read for CompReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Seek for CompReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)
    }
}

/// The order of enum variants implicitly defines the order of the secured
/// components within the Secure Execution image!
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq)]
pub enum ComponentKind {
    ShortPSW = 10,
    Stage3a = 30,
    Kernel = 40,
    Ramdisk = 50,
    Cmdline = 60,
    Stage3b = 70,
    SeHdr = 80,
    Ipib = 90,
}

impl ComponentKind {
    pub fn tweak_prefix(&self) -> u16 {
        self.clone() as u16
    }

    pub fn from_tweak_prefix(value: u16) -> Self {
        // Safety: `value` must correspond to a discriminant value of `Self`
        unsafe { std::mem::transmute(value) }
    }
}

impl Display for ComponentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(
            &match self {
                Self::Kernel => "Linux kernel",
                Self::Ramdisk => "ramdisk",
                Self::Cmdline => "kernel cmdline",
                Self::Stage3a => "stage3a",
                Self::Stage3b => "stage3b",
                Self::SeHdr => "Secure Execution header",
                Self::Ipib => "IPIB",
                Self::ShortPSW => "short PSW",
            }
            .to_string(),
            f,
        )
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct CompTweakPrefV1 {
    pub comp_prefix: u16,
    pub rand: [u8; 6],
}
impl CompTweakPrefV1 {
    fn to_u64(&self) -> u64 {
        let mut bytes_be = self.comp_prefix.to_be_bytes().to_vec();
        bytes_be.extend_from_slice(self.rand.as_slice());
        assert_eq!(bytes_be.len(), 8);
        // Safety: `bytes_be ` is guaranteed to be 8 bytes long.
        u64::from_be_bytes(bytes_be.try_into().unwrap())
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct CompTweakV1 {
    pub pref: CompTweakPrefV1,
    pub pg_idx: u64,
}

impl CompTweakV1 {
    pub fn new(kind: ComponentKind) -> Result<Self> {
        let pref = CompTweakPrefV1 {
            comp_prefix: kind.tweak_prefix(),
            rand: random_array()?,
        };

        Ok(Self { pref, pg_idx: 0 })
    }

    pub const fn comp_prefix(&self) -> u16 {
        self.pref.comp_prefix
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use deku::{DekuContainerRead, DekuContainerWrite};
    use proptest::{
        prelude::{Just, Strategy},
        prop_assert_eq, prop_oneof, proptest,
    };

    use super::{ComponentCheckCtx, ComponentKind};
    use crate::se_img_comps::{check_components, kernel::S390Kernel, CompTweakPrefV1, CompTweakV1};

    fn component_kind_strategy() -> impl Strategy<Value = ComponentKind> {
        prop_oneof![
            Just(ComponentKind::ShortPSW),
            Just(ComponentKind::Stage3a),
            Just(ComponentKind::Kernel),
            Just(ComponentKind::Ramdisk),
            Just(ComponentKind::Cmdline),
            Just(ComponentKind::Stage3b),
            Just(ComponentKind::SeHdr),
            Just(ComponentKind::Ipib),
        ]
    }

    proptest! {
        #[test]
        fn tweak_prefix_back_to_original(kind in component_kind_strategy()) {
            let prefix = kind.tweak_prefix();
            prop_assert_eq!(kind, ComponentKind::from_tweak_prefix(prefix));
        }
    }

    #[test]
    fn compctx() {
        let ctx = ComponentCheckCtx::new();
        assert_eq!(
            ctx.max_kernel_cmdline_size,
            S390Kernel::LEGACY_MAX_COMMAND_LINE_SIZE
        );
    }

    #[test]
    fn test_check_components() {
        check_components(&mut []).unwrap();
    }

    #[test]
    fn comptweak_v1() {
        let tweak = CompTweakV1 {
            pref: CompTweakPrefV1 {
                comp_prefix: 3,
                rand: [157, 239, 44, 103, 219, 118],
            },
            pg_idx: 0,
        };
        let bytes = [0, 3, 157, 239, 44, 103, 219, 118, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(tweak.pref.to_u64(), 1018075497880438);
        assert_eq!(tweak.to_bytes().unwrap(), bytes,);
        assert_eq!(CompTweakV1::from_bytes((&bytes, 0)).unwrap().1, tweak);

        let tweak = CompTweakV1 {
            pref: CompTweakPrefV1 {
                comp_prefix: 0,
                rand: [0; 6],
            },
            pg_idx: 0,
        };
        let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(tweak.pref.to_u64(), 0);
        assert_eq!(tweak.to_bytes().unwrap(), bytes,);
        assert_eq!(CompTweakV1::from_bytes((&bytes, 0)).unwrap().1, tweak);
    }
}

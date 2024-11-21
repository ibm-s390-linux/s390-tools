// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{Read, Seek, SeekFrom};

use pvimg::error::{Error, Result};

use super::{
    CompReader, ComponentCheckCtx, ComponentCheckTrait, ComponentKind, ComponentTrait,
    ReadSeekDebug,
};

#[derive(Debug)]
pub struct S390Kernel(CompReader);

impl S390Kernel {
    const ELF_MAGIC: [u8; Self::ELF_MAGIC_SIZE] = [0x7f, 0x45, 0x4c, 0x46];
    const ELF_MAGIC_OFF: u64 = 0x0;
    const ELF_MAGIC_SIZE: usize = 4;
    const KERNEL_COMMAND_LINE_SIZE_ADDR: u64 = 0x10430;
    const KERNEL_COMMAND_LINE_SIZE_LEN: usize = 8;
    pub const KERNEL_ENTRY: u64 = 0x10000;
    pub const LEGACY_MAX_COMMAND_LINE_SIZE: usize = 896;
    const S390EP: [u8; Self::S390EP_SIZE] = [0x53, 0x33, 0x39, 0x30, 0x45, 0x50];
    // Location of "S390EP" in a Linux binary (see arch/s390/boot/head.S)
    const S390EP_OFFS: u64 = 0x10008;
    const S390EP_SIZE: usize = 6;

    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self(CompReader { reader })
    }

    fn is_elf_file(&mut self) -> Result<bool> {
        self.seek(SeekFrom::Start(Self::ELF_MAGIC_OFF))?;
        let mut buf = [0x0_u8; Self::ELF_MAGIC_SIZE];
        self.read_exact(&mut buf)?;
        Ok(buf == Self::ELF_MAGIC)
    }

    fn is_s390x_kernel(&mut self) -> Result<bool> {
        self.seek(SeekFrom::Start(Self::S390EP_OFFS))?;
        let mut buf = [0_u8; Self::S390EP_SIZE];
        self.read_exact(&mut buf)?;
        Ok(buf == Self::S390EP)
    }

    fn read_max_kernel_cmdline_size(&mut self) -> Result<usize> {
        self.seek(SeekFrom::Start(Self::KERNEL_COMMAND_LINE_SIZE_ADDR))?;
        let mut buf = [0x0_u8; Self::KERNEL_COMMAND_LINE_SIZE_LEN];
        self.read_exact(&mut buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::NoS390Kernel,
            _ => e.into(),
        })?;
        let mut max_size = u64::from_be_bytes(buf).try_into()?;
        if max_size == 0 {
            max_size = Self::LEGACY_MAX_COMMAND_LINE_SIZE;
        }
        Ok(max_size)
    }
}

impl Read for S390Kernel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for S390Kernel {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ComponentCheckTrait for S390Kernel {
    fn check(&mut self, _ctx: &ComponentCheckCtx) -> Result<()> {
        if self.is_elf_file()? {
            return Err(Error::UnexpectedElfFile);
        }
        if !self.is_s390x_kernel()? {
            return Err(Error::NoS390Kernel);
        }
        Ok(())
    }

    fn init_ctx(&mut self, ctx: &mut ComponentCheckCtx) -> Result<()> {
        ctx.max_kernel_cmdline_size = self.read_max_kernel_cmdline_size()?;
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for S390Kernel {
    fn secure_mode(&self) -> bool {
        true
    }

    fn kind(&self) -> ComponentKind {
        ComponentKind::Kernel
    }
}

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
pub struct Cmdline {
    comp: CompReader,
    last_value: Option<u8>,
}

impl Cmdline {
    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self {
            comp: CompReader { reader },
            last_value: None,
        }
    }
}

impl Read for Cmdline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Make sure that the kernel cmdline always is C NUL-terminated.
        let size = self.comp.read(buf)?;
        // Store last value
        if size > 0 {
            self.last_value = Some(buf[size - 1]);
            return Ok(size);
        }
        if buf.is_empty() {
            return Ok(size);
        }

        // EOF has been reached, check for NUL-Terminator
        assert!(size == 0);

        // Was the last value a NUL-Terminator?
        if self.last_value.is_some_and(|x| x == b'\0') {
            return Ok(size);
        }
        // Store a NUL-Terminator in buf so the next `read(...)` call will stop.
        buf[0] = b'\0';
        self.last_value = Some(buf[0]);
        Ok(1)
    }
}

impl Seek for Cmdline {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        // Invalidate last value after seeking
        self.last_value = None;
        self.comp.seek(pos)
    }
}

impl ComponentCheckTrait for Cmdline {
    fn check(&mut self, ctx: &ComponentCheckCtx) -> Result<()> {
        let mut buf = vec![];
        let size = self.read_to_end(&mut buf)?;
        if size > ctx.max_kernel_cmdline_size {
            return Err(Error::KernelCmdlineTooLarge {
                size,
                max_size: ctx.max_kernel_cmdline_size,
            });
        }

        Ok(())
    }

    fn init_ctx(&mut self, _ctx: &mut ComponentCheckCtx) -> Result<()> {
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for Cmdline {
    fn kind(&self) -> ComponentKind {
        ComponentKind::Cmdline
    }

    fn secure_mode(&self) -> bool {
        true
    }
}

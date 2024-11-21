// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{Read, Seek};

use pvimg::error::Result;
use pvimg::secured_comp::ComponentTrait;

use super::ComponentKind;
use super::{CompReader, ComponentCheckCtx, ComponentCheckTrait, ReadSeekDebug};

#[derive(Debug)]
pub struct SeHdrComp(pub CompReader);

impl SeHdrComp {
    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self(CompReader { reader })
    }
}

impl Seek for SeHdrComp {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Read for SeHdrComp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl ComponentCheckTrait for SeHdrComp {
    fn check(&mut self, _ctx: &ComponentCheckCtx) -> Result<()> {
        Ok(())
    }

    fn init_ctx(&mut self, _ctx: &mut ComponentCheckCtx) -> Result<()> {
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for SeHdrComp {
    fn kind(&self) -> ComponentKind {
        ComponentKind::SeHdr
    }

    fn secure_mode(&self) -> bool {
        false
    }
}

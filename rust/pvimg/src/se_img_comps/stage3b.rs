// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{Read, Seek};

use pvimg::error::Result;
use pvimg::secured_comp::ComponentTrait;

use super::ComponentKind;
use super::{CompReader, ComponentCheckCtx, ComponentCheckTrait, ReadSeekDebug};

#[derive(Debug)]
pub struct Stage3b(CompReader);

impl Stage3b {
    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self(CompReader::new(reader))
    }
}

impl Read for Stage3b {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Stage3b {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ComponentCheckTrait for Stage3b {
    fn check(&mut self, _ctx: &ComponentCheckCtx) -> Result<()> {
        Ok(())
    }

    fn init_ctx(&mut self, _ctx: &mut ComponentCheckCtx) -> Result<()> {
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for Stage3b {
    fn kind(&self) -> ComponentKind {
        ComponentKind::Stage3b
    }

    fn secure_mode(&self) -> bool {
        true
    }
}

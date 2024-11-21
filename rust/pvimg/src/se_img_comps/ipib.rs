// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{Read, Seek};

use pvimg::error::Result;
use pvimg::secured_comp::ComponentTrait;

use super::ComponentKind;
use super::{CompReader, ComponentCheckCtx, ComponentCheckTrait, ReadSeekDebug};

#[derive(Debug)]
pub struct Ipib(CompReader);

impl Ipib {
    pub fn new(reader: Box<dyn ReadSeekDebug>) -> Self {
        Self(CompReader { reader })
    }
}

impl Read for Ipib {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Ipib {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ComponentCheckTrait for Ipib {
    fn check(&mut self, _ctx: &ComponentCheckCtx) -> Result<()> {
        Ok(())
    }

    fn init_ctx(&mut self, _ctx: &mut ComponentCheckCtx) -> Result<()> {
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for Ipib {
    fn secure_mode(&self) -> bool {
        false
    }

    fn kind(&self) -> ComponentKind {
        ComponentKind::Ipib
    }
}

// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{Cursor, Read, Seek};

use pv::{request::SeImgMetaData, static_assert};
use pvimg::error::Result;

use super::{
    bootloader::{STAGE3A_BSS_ADDRESS, STAGE3A_BSS_SIZE},
    CompReader, ComponentCheckCtx, ComponentCheckTrait, ComponentKind, ComponentTrait,
};

#[derive(Debug)]
pub struct ImgMetaData(CompReader);
static_assert!(ImgMetaData::OFFSET == SeImgMetaData::OFFSET);

impl ImgMetaData {
    pub const MAX_SIZE: u64 = STAGE3A_BSS_SIZE;
    pub const OFFSET: u64 = STAGE3A_BSS_ADDRESS;

    pub fn new(ipib_off: u64, hdr_off: u64) -> Result<Self> {
        let data = SeImgMetaData::new_v1(hdr_off, ipib_off);

        let reader = Box::new(Cursor::new(data.as_bytes().to_owned()));
        Ok(Self(CompReader { reader }))
    }
}

impl Read for ImgMetaData {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for ImgMetaData {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl ComponentCheckTrait for ImgMetaData {
    fn check(&mut self, _ctx: &ComponentCheckCtx) -> Result<()> {
        Ok(())
    }

    fn init_ctx(&mut self, _ctx: &mut ComponentCheckCtx) -> Result<()> {
        Ok(())
    }
}

impl ComponentTrait<ComponentKind> for ImgMetaData {
    fn kind(&self) -> ComponentKind {
        ComponentKind::ImgMetaData
    }

    fn secure_mode(&self) -> bool {
        false
    }
}

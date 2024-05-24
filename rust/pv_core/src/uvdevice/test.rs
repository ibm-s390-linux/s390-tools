// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(test)]

use std::{
    ffi::{c_int, c_ulong},
    os::unix::prelude::FromRawFd,
    sync::{Mutex, MutexGuard},
};

use super::*;
use lazy_static::lazy_static;

lazy_static! {
    /// needed to serialize all tests as tests operate on static data required by the mock
    static ref TEST_LOCK: Mutex<()> = Mutex::new(());
    /// exists to have a lazy static mod variable
    static ref IOCTL_MTX: Mutex<IoctlCtx> = Mutex::new(IoctlCtx::new());
}

fn get_lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct IoctlCtx {
    modify: Box<dyn FnMut(&mut ffi::uvio_ioctl_cb) -> i32 + Send + Sync>,
    exp_cmd: c_ulong,
    called: bool,
}

impl IoctlCtx {
    pub fn exp_cmd(&mut self, cmd: c_ulong) -> &mut Self {
        self.exp_cmd = cmd;
        self
    }

    pub fn set_mdfy<F>(&mut self, mdfy: F) -> &mut Self
    where
        F: FnMut(&mut ffi::uvio_ioctl_cb) -> c_int + 'static + Send + Sync,
    {
        self.modify = Box::new(mdfy);
        self
    }

    pub fn reset(&mut self) -> bool {
        let old = self.called;
        self.called = false;
        old
    }

    fn new() -> Self {
        Self {
            modify: Box::new(|_| -1),
            exp_cmd: 0,
            called: false,
        }
    }
}

pub mod mock_libc {
    use super::*;

    pub unsafe fn ioctl(fd: c_int, cmd: c_ulong, data: *mut ffi::uvio_ioctl_cb) -> c_int {
        let mut ctx = get_lock(&IOCTL_MTX);
        assert!(!ctx.called, "IOCTL called more than once");
        ctx.called = true;

        assert_eq!(cmd, ctx.exp_cmd, "IOCTL cmd mismatch");
        assert_eq!(fd, 17, "IOCTL fd mismatch");

        let data_ref: &mut ffi::uvio_ioctl_cb = &mut *data;

        (ctx.modify)(data_ref)
    }
}

impl ffi::uvio_ioctl_cb {
    fn addr_eq(&self, exp: u64) -> &Self {
        assert_eq!(
            self.argument_addr, exp,
            "ioctl arg addr not eq: {} == {}",
            self.argument_addr, exp
        );
        self
    }

    fn size_eq(&self, exp: u32) -> &Self {
        assert_eq!(
            self.argument_len, exp,
            "ioctl arg len not eq: {} == {}",
            self.argument_len, exp
        );
        self
    }

    fn set_rc(&mut self, rc: u16) -> &mut Self {
        self.uv_rc = rc;
        self
    }

    fn set_rrc(&mut self, rrc: u16) -> &mut Self {
        self.uv_rrc = rrc;
        self
    }
}

const TEST_CMD: u64 = 17;
struct TestCmd(Option<Vec<u8>>);
impl UvCmd for TestCmd {
    const UV_IOCTL_NR: u8 = 42;

    fn cmd(&self) -> u64 {
        TEST_CMD
    }

    fn rc_fmt(&self, _rc: u16, _rrc: u16) -> Option<&'static str> {
        None
    }

    fn data(&mut self) -> Option<&mut [u8]> {
        match &mut self.0 {
            None => None,
            Some(d) => Some(d.as_mut_slice()),
        }
    }
}

impl UvDevice {
    /// use some random fd for  `uvdevice` its OK, as the ioctl is mocked and never touches the
    /// passed file
    fn test_dev() -> Self {
        UvDevice(unsafe { File::from_raw_fd(17) })
    }
}

#[test]
fn ioctl_fail() {
    let _m = get_lock(&TEST_LOCK);

    let mut mock_cmd = TestCmd(None);

    get_lock(&IOCTL_MTX).exp_cmd(TEST_CMD).set_mdfy(|_| -1);

    let uv = UvDevice::test_dev();

    let res = uv.send_cmd(&mut mock_cmd);
    assert!(get_lock(&IOCTL_MTX).reset(), "IOCTL was never called");
    assert!(matches!(res, Err(Error::Io(_))));
}

#[test]
fn ioctl_simpleo() {
    let _m = get_lock(&TEST_LOCK);

    let mut mock_cmd = TestCmd(None);

    get_lock(&IOCTL_MTX).exp_cmd(TEST_CMD).set_mdfy(|cb| {
        cb.set_rc(1).addr_eq(0).size_eq(0);
        0
    });

    let uv = UvDevice::test_dev();
    let res = uv.send_cmd(&mut mock_cmd);
    assert!(get_lock(&IOCTL_MTX).reset(), "IOCTL was never called");
    assert!(res.is_ok());
}

#[test]
fn ioctl_simple_err() {
    let _m = get_lock(&TEST_LOCK);

    let mut mock_cmd = TestCmd(None);

    get_lock(&IOCTL_MTX).exp_cmd(TEST_CMD).set_mdfy(|cb| {
        cb.set_rc(17).set_rrc(3).addr_eq(0).size_eq(0);
        0
    });

    let uv = UvDevice::test_dev();
    let res = uv.send_cmd(&mut mock_cmd);
    assert!(get_lock(&IOCTL_MTX).reset(), "IOCTL was never called");
    assert!(matches!(res, Err(Error::Uv{rc, rrc, ..}) if rc == 17 && rrc == 3 ));
}

#[test]
fn ioctl_write_data() {
    let _m = get_lock(&TEST_LOCK);

    let cmd_data = vec![0u8; 32];
    let cmd_data_len = cmd_data.len();
    let data_addr = cmd_data.as_ptr() as u64;

    let mut mock_cmd = TestCmd(Some(cmd_data));

    get_lock(&IOCTL_MTX).exp_cmd(TEST_CMD).set_mdfy(move |cb| {
        cb.set_rc(1).addr_eq(data_addr).size_eq(32);
        unsafe {
            ::libc::memset(cb.argument_addr as *mut ::libc::c_void, 0x42, cmd_data_len);
        }
        0
    });

    let uv = UvDevice::test_dev();
    let res = uv.send_cmd(&mut mock_cmd);
    assert!(get_lock(&IOCTL_MTX).reset(), "IOCTL was never called");
    assert_eq!(res.unwrap(), UvcSuccess::RC_SUCCESS);
}

#[test]
fn ioctl_read_data() {
    let _m = get_lock(&TEST_LOCK);

    let cmd_data = vec![42u8; 32];
    let cmd_data_len = cmd_data.len();
    let data_addr = cmd_data.as_ptr() as u64;
    let data_exp = cmd_data.clone();

    let mut mock_cmd = TestCmd(Some(cmd_data));

    get_lock(&IOCTL_MTX).exp_cmd(TEST_CMD).set_mdfy(move |cb| {
        cb.set_rc(1).addr_eq(data_addr).size_eq(32);
        unsafe {
            let data = std::slice::from_raw_parts(cb.argument_addr as *const u8, cmd_data_len);
            assert_eq!(data, data_exp);
        }
        0
    });

    let uv = UvDevice::test_dev();
    let res = uv.send_cmd(&mut mock_cmd);
    assert!(get_lock(&IOCTL_MTX).reset(), "IOCTL was never called");
    assert_eq!(res.unwrap(), UvcSuccess::RC_SUCCESS);
}

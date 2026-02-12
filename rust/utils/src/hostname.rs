// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2026

use std::{ffi::CStr, io};

/// Returns the maximum hostname length supported by the system.
///
/// # Returns
///
/// The maximum hostname length in bytes, excluding the NUL terminator.
fn max_hostname_len() -> usize {
    const _POSIX_HOST_NAME_MAX: usize = 255;

    // SAFETY: sysconf is safe to call with _SC_HOST_NAME_MAX and only reads system configuration without side effects.
    let n = unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) };
    if n < 0 {
        _POSIX_HOST_NAME_MAX
    } else {
        n.try_into().unwrap()
    }
}

/// Retrieves the system hostname using libc gethostname.
///
/// # Returns
///
/// Returns `Ok(String)` containing the hostname on success, or an `Err(io::Error)` otherwise.
///
/// # Examples
///
/// ```rust,no_run
/// use utils::gethostname;
///
/// let hostname = gethostname().expect("Failed to get hostname");
/// println!("Hostname: {}", hostname);
/// ```
pub fn gethostname() -> io::Result<String> {
    // Add space for NUL terminator
    let buf_len = max_hostname_len().checked_add(1).unwrap();
    let mut buf = vec![0u8; buf_len];

    // SAFETY: `buf` is a byte array large enough for storing the result of
    // `gethostname` as the max length was just checked before.
    let result = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if result != 0 {
        // libc::gethostname returns -1 on error and sets errno
        return Err(io::Error::last_os_error());
    }

    // If it is not NUL-terminated, then add the NUL-termination at the end
    if !buf.contains(&0) {
        if let Some(last) = buf.last_mut() {
            *last = 0;
        }
    }

    assert!(isize::try_from(buf_len).unwrap() <= isize::MAX);

    // SAFETY: We made sure that `buf` is:
    // 1. NUL-terminated
    // 2. A single allocation (vec![...] was used for the allocation)
    // 3. `buf_len` is <= isize::MAX (verified by assertion above)
    // Therefore, it's safe to construct a CStr from the buffer pointer.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    Ok(cstr.to_string_lossy().into_owned())
}

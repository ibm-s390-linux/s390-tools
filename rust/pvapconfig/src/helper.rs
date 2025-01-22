// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! Collection of helper functions for pvapconfig
//

use regex::Regex;
use std::error::Error;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

pub const PATH_PVAPCONFIG_LOCK: &str = "/run/lock/pvapconfig.lock";

/// Read sysfs file into string
pub fn sysfs_read_string(fname: &str) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(fname)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let trimmed_content = String::from(content.trim());
    Ok(trimmed_content)
}

/// Write string into sysfs file
pub fn sysfs_write_string(fname: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).open(fname)?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

/// Read sysfs file content and parse as i32 value
pub fn sysfs_read_i32(fname: &str) -> Result<i32, Box<dyn Error>> {
    let content = sysfs_read_string(fname)?;
    Ok(content.parse::<i32>()?)
}

/// Write an i32 value into a sysfs file
pub fn sysfs_write_i32(fname: &str, value: i32) -> Result<(), Box<dyn Error>> {
    sysfs_write_string(fname, &value.to_string())
}

/// For a given (sysfs) directory construct a list of all subdirs
/// and give it back as a vector of strings. If there is no subdir,
/// the vector is empty.
pub fn sysfs_get_list_of_subdirs(dname: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut v: Vec<String> = Vec::new();
    let entries = fs::read_dir(dname)?;
    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            _ => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        let fname = match entry.file_name().into_string() {
            Ok(s) => s,
            _ => continue,
        };
        v.push(fname);
    }
    Ok(v)
}

/// For a given (sysfs) directory construct a list of all subdirs which
/// match to the given regular expression and give the list back as a
/// vector of strings. If there is no subdir, the vector is empty.
pub fn sysfs_get_list_of_subdirs_matching_regex(
    dname: &str,
    regex: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut v: Vec<String> = Vec::new();
    let re = Regex::new(regex)?;
    let entries = sysfs_get_list_of_subdirs(dname)?;
    for entry in entries {
        if re.is_match(&entry) {
            v.push(entry);
        }
    }
    Ok(v)
}

/// LockFile for inter-process locking
///
/// Simple class for process locking for pvapconfig.
/// The lock concept is simple: The existence of a file is used as the
/// locking indicator. If the file exists something is locked, if it does
/// not exist something is not locked. In the lock file the PID of the
/// process created the file ("owning this file") is written in.
/// With the ProcessLock object leaving scope the associated lock file
/// is automatically deleted. It is assumed that the creation of a file
/// is an atomic operation - that's true for most filesystems but may
/// cause problems with network based filesystems.
/// Example:
/// ```
/// let lock = LockFile::lock("/var/lock/process.lock");
/// assert!(lock.is_ok());
/// let lock2 = LockFile::lock("/var/lock/process.lock");
/// assert!(lock2.is_err());
/// drop(lock);
/// let lock3 = LockFile::lock("/var/lock/process.lock");
/// assert!(lock3.is_ok());
/// ```
#[derive(Debug)]
pub struct LockFile {
    lockfile: PathBuf,
}

impl LockFile {
    /// Try to establish the lock file.
    /// Upon success the given file is fresh created and has the pid of this
    /// process written in. The function returns a new LockFile object
    /// which has implemented the Drop Trait. So with this object going out
    /// of scope the lock file is deleted. If establishing the lock file
    /// fails for any reason (for example the file already exists), the
    /// function fails with returning an Error string. This function does
    /// NOT panic if establishing the lock file fails for any reason. If
    /// the lock file could be esablished but writing in the PID fails, a
    /// warning is printed but the function continues with returning a
    /// LockFile object.
    pub fn try_lock(fname: &str) -> Result<Self, String> {
        let lockfile = PathBuf::from(fname);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lockfile)
        {
            Err(err) => {
                return Err(format!(
                    "Failure trying to create lock file {fname}: {err:?}."
                ))
            }
            Ok(f) => f,
        };
        let _ = file
            .write(format!("{}", std::process::id()).as_bytes())
            .map_err(|err| {
                println!("Warning: could not write PID into lockfile {fname}: {err:?}.")
            });
        Ok(Self { lockfile })
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lockfile).map_err(|err| {
            println!(
                "Warning: could not remove lockfile {}: {err:?}.",
                self.lockfile.display()
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::TemporaryDirectory;

    // Only very simple tests

    #[test]
    fn test_sysfs_read_string() {
        let r = sysfs_read_string("/proc/cpuinfo");
        assert!(r.is_ok());
    }
    #[test]
    fn test_sysfs_read_i32() {
        let r = sysfs_read_i32("/proc/sys/kernel/random/entropy_avail");
        assert!(r.is_ok());
    }
    #[test]
    fn test_sysfs_get_list_of_subdirs() {
        let r = sysfs_get_list_of_subdirs("/proc/self");
        assert!(r.is_ok());
        let v = r.unwrap();
        assert!(!v.is_empty());
    }
    #[test]
    fn test_sysfs_get_list_of_subdirs_matching_regex() {
        let r = sysfs_get_list_of_subdirs_matching_regex("/proc/self", "fd.*");
        assert!(r.is_ok());
        let v = r.unwrap();
        assert!(!v.is_empty());
        for e in v {
            assert!(e.strip_prefix("fd").is_some());
        }
    }
    #[test]
    fn test_sysfs_write_i32() {
        let temp_dir =
            TemporaryDirectory::new().expect("creating a temporary directory should work");
        let test_path = temp_dir.path().join("test");
        let test_path = test_path.as_os_str().to_str().expect("should work");
        let mut file = File::create(test_path).unwrap();
        let _ = file.write_all(b"XYZ");
        drop(file);
        let r = sysfs_read_i32(test_path);
        assert!(r.is_err());
        let r = sysfs_write_i32(test_path, 999);
        assert!(r.is_ok());
        let r = sysfs_read_i32(test_path);
        assert!(r.is_ok());
        let v = r.unwrap();
        assert!(v == 999);
    }
    #[test]
    fn test_lockfile() {
        let temp_dir =
            TemporaryDirectory::new().expect("creating a temporary directory should work");
        let file_path = temp_dir.path().join("my.lock");
        let file_path_str = file_path.to_str().expect("should work");

        let r1 = LockFile::try_lock(file_path_str);
        assert!(r1.is_ok());
        let r2 = LockFile::try_lock(file_path_str);
        assert!(r2.is_err());
        drop(r1);
        let r3 = LockFile::try_lock(file_path_str);
        assert!(r3.is_ok());
    }
}

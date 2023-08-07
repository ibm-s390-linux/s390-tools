# s390-tools tools written in rust

## Setting up rust development and build environment
Please refer to the official documentation to set up a working rust environment:
https://www.rust-lang.org/learn/get-started

## Building rust code
### s390-tools build system
If `cargo` is installed  a simple `make` should do the job. Note that,
compiling rust programs take significantly longer than C code. To closely
monitor the progress use `make V=1` By default release builds are made.

With `make CARGOFLAGS=<flags>` one can pass additional flags to cargo.
With `make HAVE_CARGO=0` one can turn of any compilation that requires cargo.
With `make CARGO=<...>` one can set the cargo binary

### cargo
If you need to run cargo directly, `cd` to each project you want to build and
issue your cargo commands. Do **NOT** forget to specify `--release` if you are
building tools for a release. The s390-tools expect the environment variable
`S390_TOOLS_RELEASE` to be present at build time. This is the version string the
rust tools provide.

Tip: You can use `make version` to get the version string.

## Internal Libraries
* __utils__ _Library for rust tools that bundles common stuff for the 390-tools_
	* currently only provides a macro to get the `S390_TOOLS_RELEASE` string

* __pv__ _Library for pv tools, providing uvdevice access, encryption utilities, and utilities for generating UV-request_
	* requires openssl and libcurl for the feature `request`; use `HAVE_<OPENSSL|CURL>=0` to
	  disable build that use pv with the request feature.


## Tools
* __pvsecret__ _Manage secrets for IBM Secure Execution guests_
	* requires pv with the `request` feature

## Writing new tools
We encourage to use Rust for new tools. However, for some use cases it makes
sense to use C and C is still allowed to be used for a new tool/library.
Exiting tools may be rewritten in Rust.

### What (third-party) crates can be used for s390-tools?
A huge list of libraries are made available through Rusts' ecosystem and is one
of many upsides. However, just like with Coding Style Guidelines, it is
important to limit the usage of those libraries so that within a project,
everyone is on the same page and that code written in Rust uses similar
approaches. It makes it easier for code review and maintainability in general.

The following list of crates should cover a wide variety of use cases. This list
is a start, but can change over time.

* [anyhow](https://crates.io/crates/anyhow)
    * Flexible concrete Error type built on std::error::Error
* [byteorder](https://crates.io/crates/byteorder)
    * Library for reading/writing numbers in big-endian and little-endian.
* [cfg-if](https://crates.io/crates/cfg-if)
    * A macro to ergonomically define an item depending on a large number of
      #[cfg] parameters. Structured like an if-else chain, the first matching
      branch is the item that gets emitted.
* [clap](https://crates.io/crates/clap)
    * A simple to use, efficient, and full-featured Command Line Argument Parser
* [curl](https://crates.io/crates/curl)
    * Rust bindings to libcurl for making HTTP requests
* [libc](https://crates.io/crates/libc)
    * Raw FFI bindings to platform libraries like libc.
* [log](https://crates.io/crates/log)
    * A lightweight logging facade for Rust
* [openssl](https://crates.io/crates/openssl)
    * OpenSSL bindings
* [serde](https://crates.io/crates/serde)
    * A generic serialization/deserialization framework
* [serde_yaml](https://crates.io/crates/serde_yaml)
    * YAML data format for Serde
* [thiserror](https://crates.io/crates/thiserror)
    * derive(Error)
* [zerocopy](https://crates.io/crates/zerocopy)
    * Utilities for zero-copy parsing and serialization

Dependencies used by the crates listed above can be used, too.

### Add new tool
To add a new tool issue `cargo new <TOOLNAME>` in the `rust` directory.

Add the tool to the _s390-tools_ build system:
```Makefile
CARGO_TARGETS := TOOLNAME
```

### Versions
Do not communicate the version defined in the `toml` file by default. Use
`release_string` from the `rust/utils` crate instead:

```rust
use utils::release_string;

fn print_version() {
    println!(
        "{} version {}\nCopyright IBM Corp. 2023",
        env!("CARGO_PKG_NAME"), // collapses into the crates name
        release_string!() // this (very likely) collapses into a compile time constant
    );
}
```

### Unsafe rust
rust allows you to write unsafe rust. Try to avoid it, it can make rust
_unsafe_.  If you need to, e.g. interacting with other languages like C, keep
the `unsafe` block as small as possible and add a reasoning using `// SAFETY:
`why this code is safe. Example:

```rust
// Get the raw pointer and do an ioctl.
//
// SAFETY: the passed pointer points to a valid memory region that
// contains the expected C-struct. The struct outlives this function.
unsafe {
    let ptr: *mut ffi::uvio_ioctl_cb = cb as *mut _;
    rc = ioctl(raw_fd, cmd, ptr);
}
```

### Coding style
Make `cargo fmt` and `cargo clippy` happy!

### Testing
Prefer writing tests using rustdoc. Use explicit rust tests for more edge case tests.

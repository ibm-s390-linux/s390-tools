<!--
SPDX-License-Identifier: MIT

Copyright 2024 IBM Corp.
-->
# s390_pv - library for pv-tools

This library is intended to be used by tools and libraries that
are used for creating and managing [IBM Secure Execution](https://www.ibm.com/docs/en/linux-on-systems?topic=virtualization-secure-execution) guests.
`pv` provides abstraction layers for encryption, secure memory management,
and accessing the uvdevice.

If your project is not targeted to provide tooling for and/or managing of IBM Secure execution
guests, do **not** use this crate.

## OpenSSL 1.1.0+ is required

If you do not need any OpenSSL features use  [s390_pv_core](https://crates.io/crates/s390_pv_core).
This crate reexports all symbols from `s390_pv_core`. If your project uses this crate do **not** include `s390_pv_core` as well.

## Import crate
The recommended way of importing this crate is:
```bash
cargo add s390_pv --rename pv
```

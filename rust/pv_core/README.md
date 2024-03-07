<!--
SPDX-License-Identifier: MIT

Copyright 2024 IBM Corp.
-->
# s390_pv_core - basic library for pv-tools

This library is intended to be used by tools and libraries that
are used for creating and managing [IBM Secure Execution](https://www.ibm.com/docs/en/linux-on-systems?topic=virtualization-secure-execution) guests.
`s390_pv_core` provides abstraction layers for secure memory management,
logging, and accessing the uvdevice.

If your project is not targeted to provide tooling for and/or managing of IBM Secure execution
guests, do **not** use this crate.

It does not provide any cryptographic operations through OpenSSL.
For this use [s390_pv](https://crates.io/crates/s390_pv_core) which reexports all symbols from this crate.
If your project uses `s390_pv` crate do **not** include `s390_pv_core` as well.

## Import crate
The recommended way of importing this crate is:
```bash
cargo add s390_pv_core --rename pv_core
```

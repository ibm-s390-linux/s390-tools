// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

fn main() {
    #[cfg(target_arch = "s390x")]
    cc::Build::new().file("src/stfle.c").compile("stfle");
    #[cfg(not(target_arch = "s390x"))]
    {
        println!("cargo:warning=cpacfinfo will have no functionality on non s390x architectures!");
        cc::Build::new().file("src/noop.c").compile("stfle");
    }
    println!("cargo:rerun-if-changed=src/stfle.c")
}

// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! For processing descriptions

pub const FACILITIES_DESC: &str = r#"Query Ultravisor Information
Initialize Ultravisor
Create Secure Configuration
Destroy Secure Configuration
Create Secure CPU
Destroy Secure CPU
Convert to Secure Storage
Convert from Secure Storage
Set Shared Access
Remove Shared Access
Reserved
Set Secure Parameters
Destroy Secure Storage
Unpack Image
Verify Image
Perform CPU Reset
Perform Initial CPU Reset
Set CPU State
Prepare for Reset
Perform CPU Clear Reset
Unshare All
Pin Shared Storage
Unpin Shared Storage
Destroy Secure Configuration Fast
Initiate Configuration Dump
Dump Configuration Storage State
Dump CPU State
Complete Configuration Dump
Retrieve Attestation Measurement
Add Secret
List Secrets
Lock Secrets
Verify Large Frame
Retrieve Secret"#;

pub const FEATURE_INDICATIONS_DESC: &str = r#"Reserved
Adapter interrupt virtualization is supported
Reserved
Reserved
AP passthrough is supported
AP interpretion passthrough is supported"#;

pub const SUPP_ADD_SECRET_PCF_DESC: &str = r#"Disable dumping"#;

pub const SUPP_ATT_PFLAGS_DESC: &str = r#"Reserved
The attestation request contains an optional nonce
Adding the SHA-256 hash of the public host key to the additional data area for measurement.
Adding the SHA-256 hash of the public host key for the Attestation request header to the additional data area for measurement.
The Add-secret Request Stream Flag (ARSF) is a SHA-512 hash of successful add-secret tags (in order), plus a byte indicating store lock status.
Adding the 320-byte firmware attestation measurement (FWCF) to the additional data area."#;

pub const SUPP_SE_HDR_PCF_DESC: &str = r#"Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Dumping of the secure execution guest is allowed
The decrypt image ultravisor command does not decrypt the content of the specified 4K-byte block of storage. The page-list digest, the address-list digest, and the tweak-list digest are still verified.
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
PCKMO encrypt-DEA/TDEA-key functions allowed
PCKMO encrypt-AES-key functions allowed
PCKMO encrypt-ECC-key functions allowed
Reserved
Reserved
Reserved
Temporary backup-host-key use allowed
Reserved"#;

pub const SUPP_SECRET_TYPES_DESC: &str = r#"Reserved
Meta
AP-association
Plaintext
AES 128
AES 192
AES 256
AES 128 XTS
AES 256 XTS
HMAC SHA 256
HMAC SHA 512
Reserved
Reserved
Reserved
Reserved
Reserved
Reserved
ECDSA P256 private key
ECDSA P384 private key
ECDSA P521 private key
EdDSA Ed25529 private key
EdDSA Ed448 private key
Update-CCK"#;

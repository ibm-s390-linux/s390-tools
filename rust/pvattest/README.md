<!--
Copyright 2024 IBM Corp.
s390-tools is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
-->
# pvattest
## Synopsis
`pvattest [OPTIONS] <COMMAND>`
## Description
create, perform, and verify attestation measurements Create, perform, and verify
attestation measurements for IBM Secure Execution guest systems.
## Commands Overview
- **create**
<ul>
Create an attestation measurement request
</ul>

- **perform**
<ul>
Send the attestation request to the Ultravisor
</ul>

- **verify**
<ul>
Verify an attestation response
</ul>

- **check**
<ul>
Check if the attestation result matches defined policies
</ul>

## Options

`-v`, `--verbose`
<ul>
Provide more detailed output.
</ul>


`-q`, `--quiet`
<ul>
Provide less output.
</ul>


`--version`
<ul>
Print version information and exit.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvattest create
### Synopsis
`pvattest create [OPTIONS] --host-key-document <FILE> --output <FILE> --arpk <FILE> <--no-verify|--cert <FILE>>`
### Description
Create an attestation measurement request. Create attestation measurement
requests to attest an IBM Secure Execution guest. Only build attestation
requests in a trusted environment such as your Workstation. To avoid
compromising the attestation do not publish the attestation request protection
key and shred it after verification. Every 'create' will generate a new, random
protection key.
### Options

`-k`, `--host-key-document <FILE>`
<ul>
Use FILE as a host-key document. Can be specified multiple times and must be
used at least once.
</ul>


`--no-verify`
<ul>
Disable the host-key document verification. Does not require the host-key
documents to be valid. Do not use for a production request unless you verified
the host-key document beforehand.
</ul>


`-C`, `--cert <FILE>`
<ul>
Use FILE as a certificate to verify the host-key or keys. The certificates are
used to establish a chain of trust for the verification of the host-key
documents. Specify this option twice to specify the IBM Z signing key and the
intermediate CA certificate (signed by the root CA).
</ul>


`--crl <FILE>`
<ul>
Use FILE as a certificate revocation list. The list is used to check whether a
certificate of the chain of trust is revoked. Specify this option multiple times
to use multiple CRLs.
</ul>


`--offline`
<ul>
Make no attempt to download CRLs.
</ul>


`--root-ca <ROOT_CA>`
<ul>
Use FILE as the root-CA certificate for the verification. If omitted, the system
wide-root CAs installed on the system are used. Use this only if you trust the
specified certificate.
</ul>


`-o`, `--output <FILE>`
<ul>
Write the generated request to FILE.
</ul>


`-a`, `--arpk <FILE>`
<ul>
Save the protection key as unencrypted GCM-AES256 key in FILE Do not publish
this key, otherwise your attestation is compromised.
</ul>


`--add-data <FLAGS>`
<ul>
Specify additional data for the request. Additional data is provided by the
Ultravisor and returned during the attestation request and is covered by the
attestation measurement. Can be specified multiple times. Optional.
    Possible values:
        - **phkh-img**: Request the public host-key-hash of the key that decrypted the SE-image as additional-data.
        - **phkh-att**: Request the public host-key-hash of the key that decrypted the attestation request as additional-data.
        - **secret-store-hash**: Request a hash over all successful Add-secret requests and the lock state as additional-data.
        - **firmware-state**: Request the state of the firmware as additional-data.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvattest perform
### Synopsis
`pvattest perform [OPTIONS] [IN] [OUT]`
### Description
Send the attestation request to the Ultravisor. Run a measurement of this system
through ’/dev/uv’. This device must be accessible and the attestation
Ultravisor facility must be present. The input must be an attestation request
created with ’pvattest create’. Output will contain the original request and
the response from the Ultravisor.
### Arguments

`<IN>`
<ul>
Specify the request to be sent.
</ul>


`<OUT>`
<ul>
Write the result to FILE.
</ul>


### Options

`-u`, `--user-data <File>`
<ul>
Provide up to 256 bytes of user input User-data is arbitrary user-defined data
appended to the Attestation measurement. It is verified during the Attestation
measurement verification. May be any arbitrary data, as long as it is less or
equal to 256 bytes
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvattest verify
### Synopsis
`pvattest verify [OPTIONS] --input <FILE> --hdr <FILE> --arpk <FILE>`
### Description
Verify an attestation response. Verify that a previously generated attestation
measurement of an IBM Secure Execution guest is as expected. Only verify
attestation requests in a trusted environment, such as your workstation. Input
must contain the response as produced by ’pvattest perform’. The protection
key must be the one that was used to create the request by ’pvattest create’.
Shred the protection key after the verification. The header must be the IBM
Secure Execution header of the image that was attested during ’pvattest
perform’
### Options

`-i`, `--input <FILE>`
<ul>
Specify the attestation response to be verified.
</ul>


`-o`, `--output <FILE>`
<ul>
Specify the output for the verification result.
</ul>


`--hdr <FILE>`
<ul>
Specifies the header of the guest image. Can be an IBM Secure Execution image
created by genprotimg or an extracted IBM Secure Execution header. The header
must start at a page boundary.
</ul>


`-a`, `--arpk <FILE>`
<ul>
Use FILE as the protection key to decrypt the request Do not publish this key,
otherwise your attestation is compromised. Delete this key after verification.
</ul>


`--format <FORMAT>`
<ul>
Define the output format.
    Default value: 'yaml'
    Possible values:
        - **yaml**: Use yaml format.
</ul>


`-u`, `--user-data <FILE>`
<ul>
Write the user data to the FILE if any. Writes the user data, if the response
contains any, to FILE The user-data is part of the attestation measurement. If
the user-data is written to FILE the user-data was part of the measurement and
verified. Emits a warning if the response contains no user-data.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvattest check
### Synopsis
`pvattest check [OPTIONS] <IN> <OUT>`
### Description
Check if the attestation result matches defined policies. After the attestation
verification, check whether the attestation result complies with user-defined
policies.
### Arguments

`<IN>`
<ul>
Specify the attestation response to check whether the policies are validated.
</ul>


`<OUT>`
<ul>
Specify the output file for the check result.
</ul>


### Options

`--format <FORMAT>`
<ul>
Define the output format.
    Default value: 'yaml'
    Possible values:
        - **yaml**: Use yaml format.
</ul>


`-k`, `--host-key-document <FILE>`
<ul>
Use FILE to check for a host-key document. Verifies that the attestation
response contains the host-key hash of one of the specified host keys. The check
fails if none of the host-keys match the hash in the response. This parameter
can be specified multiple times.
</ul>


`--host-key-check <HOST_KEY_CHECKS>`
<ul>
Define the host-key check policy By default, all host-key hashes are checked,
and it is not considered a failure if a hash is missing from the attestation
response. Use this policy switch to trigger a failure if no corresponding hash
is found. Requires at least one host-key document.
    Possible values:
        - **att-key-hash**: Check the host-key used for the attestation request.
        - **boot-key-hash**: Check the host-key used to the boot the image.
</ul>


`-u`, `--user-data <FILE>`
<ul>
Check if the provided user data matches the data from the attestation response.
</ul>


`--secret <FILE>`
<ul>
Use FILE to include as successful Add-secret request. Checks if the Attestation
response contains the hash of all specified add secret requests-tags. The hash
is sensible to the order in which the secrets where added. This means that if
the order of adding here different from the order the add-secret requests where
sent to the UV this check will fail even though the same secrets are included in
the UV secret store. Can be specified multiple times.
</ul>


`--secret-store-locked <BOOL>`
<ul>
Check whether the guests secret store is locked or not. Compares the hash of the
secret store state to the one calculated by this option and optionally specified
add-secret-requests. If the attestation response does not contain a secret store
hash, this check fails.

Required if add-secret-requests are specified.
</ul>


`--firmware`
<ul>
Check whether the firmware is on an IBM supported version. Requires internet
access.
</ul>


`--firmware-verify-url <URL>`
<ul>
Specify the endpoint to use for firmware version verification. Use an endpoint
you trust. Requires the --firmware option.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>

<!--
Copyright 2023, 2024 IBM Corp.
s390-tools is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
-->
# pvsecret
## Synopsis
`pvsecret [OPTIONS] <COMMAND>`
## Description
Use **pvsecret** to manage secrets for IBM Secure Execution guests. **pvsecret**
can **create** add-secret requests on any architecture. On s390x systems, use
**pvsecret** to **add** the secrets to the ultravisor secret store, **list** all
secrets in the secret store, or **lock** the secret store to prevent any
modifications in the future.

The ultravisor secret store stores secrets for the IBM Secure Execution guest.
The secret store is cleared on guest reboot.

Create requests only on trusted systems that are not the IBM Secure Execution
guest where you want to inject the secrets. This approach prevents the secrets
from being in cleartext on the guest. For extra safety, do an attestation with
**pvattest** of your guest beforehand, and include the configuration UID in the
secret request using **--cuid**. Refer to **pvsecret-add** for more information.
For all certificates, revocation lists, and host-key documents, both the PEM and
DER input formats are supported.

## Commands Overview
- **create**
<ul>
Create a new add-secret request
</ul>

- **add**
<ul>
Submit an add-secret request to the Ultravisor (s390x only)
</ul>

- **lock**
<ul>
Lock the secret-store (s390x only)
</ul>

- **list**
<ul>
List all ultravisor secrets (s390x only)
</ul>

- **verify**
<ul>
Verify that an add-secret request is sane
</ul>

- **retrieve**
<ul>
Retrieve a secret from the UV secret store (s390x only)
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


## pvsecret create
### Synopsis
`pvsecret create [OPTIONS] --host-key-document <FILE> --hdr <FILE> --output <FILE> <--no-verify|--cert <FILE>> <COMMAND>`
### Description
Create add-secret requests for IBM Secure Execution guests. Only create these
requests in a trusted environment, such as your workstation. The **pvattest
create** command creates a randomly generated key to protect the request. The
generated requests can then be added on an IBM Secure Execution guest using
**pvsecret add**. The guest can then use the secrets with the use case depending
on the secret type.
Such a request is bound to a specific IBM Secure Execution image specified with
**--hdr**. Optionally, the request can be bound to a specific instance when
bound to the Configuration Unique ID from **pvattest** using **--cuid**

### Commands Overview
- **meta**
<ul>
Create a meta secret
</ul>

- **association**
<ul>
Create an association secret
</ul>

- **retrievable**
<ul>
Create a retrievable secret
</ul>

### Options

`-k`, `--host-key-document <FILE>`
<ul>
Use FILE as a host-key document. Can be specified multiple times and must be
specified at least once.
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
Use FILE as a certificate revocation list (CRL). The list is used to check
whether a certificate of the chain of trust is revoked. Specify this option
multiple times to use multiple CRLs.
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


`--hdr <FILE>`
<ul>
Specifies the header of the guest image. Can be an IBM Secure Execution image
created by 'pvimg/genprotimg' or an extracted IBM Secure Execution header.
</ul>


`-f`, `--force`
<ul>
Force the generation of add-secret requests on IBM Secure Execution guests. If
the program detects that it is running on an IBM Secure Execution guest, it
denies the generation of add-secret requests. The force flag overwrites this
behavior.
</ul>


`-o`, `--output <FILE>`
<ul>
Write the generated request to FILE.
</ul>


`--extension-secret <FILE>`
<ul>
Use the content of FILE as an extension secret. The file must be exactly 32
bytes long. If this request is the first, all subsequent requests must have the
same extension secret. Only makes sense if bit 1 of the secret control flags of
the IBM Secure Execution header is 0. Otherwise the ultravisor rejects the
request.
</ul>


`--cck <FILE>`
<ul>
Use the content of FILE as the customer-communication key (CCK) to derive the
extension secret. The file must contain exactly 32 bytes of data. If the target
guest was started with bit 1 of the secret control flag set, the ultravisor also
derives the secret from the CCK. Otherwise, the ultravisor interprets the
extension secret as a normal one. This still works if you use the same CCK for
all requests.
</ul>


`--cuid-hex <HEXSTRING>`
<ul>
Use HEXSTRING as the Configuration Unique ID. Must be a hex 128-bit unsigned big
endian number string. Leading zeros must be provided. If specified, the value
must match with the Config-UID from the attestation result of that guest. If not
specified, the CUID will be ignored by the ultravisor during the verification of
the request.
</ul>


`--cuid <FILE>`
<ul>
Use the content of FILE as the Configuration Unique ID. The file must contain
exactly 128 bit of data or a yaml with a `cuid` entry. If specified, the value
must match the Config-UID from the attestation result of that guest. If not
specified, the CUID will be ignored by the Ultravisor during the verification of
the request.
</ul>


`--flags <FLAGS>`
<ul>
Flags for the add-secret request.
    Possible values:
        - **disable-dump**: Disables host-initiated dumping for the target guest instance.
</ul>


`--user-data <FILE>`
<ul>
Use the content of FILE as user-data. Passes user data defined in FILE through
the add-secret request to the ultravisor. The user data can be up to 512 bytes
of arbitrary data, and the maximum size depends on the size of the user-signing
key:

 - No key: user data can be 512 bytes.

 - EC(secp521r1) or RSA 2048 keys: user data can be 256 bytes.

 - RSA 3072 key: user data can be 128 bytes.

The firmware ignores this data, but the request tag protects the user-data.
Optional. No user-data by default.
</ul>


`--user-sign-key <FILE>`
<ul>
Use the content of FILE as user signing key. Adds a signature calculated from
the key in FILE to the add-secret request. The file must be in DER or PEM format
containing a private key. Supported are RSA 2048 & 3072-bit and EC(secp521r1)
keys. The firmware ignores the content, but the request tag protects the
signature. The user-signing key signs the request. The location of the signature
is filled with zeros during the signature calculation. The request tag also
secures the signature. See man pvsecret verify for more details. Optional. No
signature by default.
</ul>


`--use-name`
<ul>
Do not hash the name, use it directly as secret ID. Ignored for meta-secrets.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


### pvsecret create meta
#### Synopsis
`pvsecret create meta`
#### Description
Create a meta secret. Use a meta secret to carry flags to the ultravisor without
having to provide an actual secret value. Meta secrets do not appear in the list
of secrets.

### pvsecret create association
#### Synopsis
`pvsecret create association [OPTIONS] <NAME>`
#### Description
Create an association secret. Use an association secret to connect a trusted I/O
device to a guest. The 'pvapconfig' tool provides more information about
association secrets.
#### Arguments

`<NAME>`
<ul>
String that identifies the new secret. The actual secret is set with
'--input-secret'. The name is saved in `NAME.yaml` with white-spaces mapped to
`_`.
</ul>


#### Options

`--stdout`
<ul>
Print the hashed name to stdout. The hashed name is not written to `NAME.yaml`
</ul>


`--input-secret <SECRET-FILE>`
<ul>
Path from which to read the plaintext secret. Uses a random secret if not
specified.
</ul>


`--output-secret <SECRET-FILE>`
<ul>
Save the generated secret as plaintext in SECRET-FILE. The generated secret can
be used to generate add-secret requests for a different guest with the same
secret using '--input-secret'. Destroy the secret when it is not used anymore.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


### pvsecret create retrievable
#### Synopsis
`pvsecret create retrievable [OPTIONS] --secret <SECRET-FILE> --type <TYPE> <NAME>`
`pvsecret create retr [OPTIONS] --secret <SECRET-FILE> --type <TYPE> <NAME>`
#### Description
Create a retrievable secret. A retrievable secret is stored in the per-guest
storage of the Ultravisor. A SE-guest can retrieve the secret at runtime and use
it. All retrievable secrets, but the plaintext secret, are retrieved as
wrapped/protected key objects and only usable inside the current, running
SE-guest instance.
#### Arguments

`<NAME>`
<ul>
String that identifies the new secret. The actual secret is set with '--secret'.
The name is saved in `NAME.yaml` with white-spaces mapped to `_`.
</ul>


#### Options

`--stdout`
<ul>
Print the hashed name to stdout. The hashed name is not written to `NAME.yaml`
</ul>


`--secret <SECRET-FILE>`
<ul>
Use SECRET-FILE as retrievable secret.
</ul>


`--type <TYPE>`
<ul>
Specify the secret type. Limitations to the input data apply depending on the
secret type.
    Possible values:
        - **plain**: A plaintext secret. Can be any file up to 8190 bytes long.
        - **aes**: An AES key. Must be a plain byte file 128, 192, or 256 bit long.
        - **aes-xts**: An AES-XTS key. Must be a plain byte file 512, or 1024 bit long.
        - **hmac-sha**: A HMAC-SHA key. Must be a plain byte file 512, or 1024 bit long. Special care is required when creating HMAC-SHA keys. For more Information refer to the DESCRIPTION section of the man file.
        - **ec**: An elliptic curve private key. Must be a PEM or DER file.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvsecret add
### Synopsis
`pvsecret add <FILE>`
### Description
Submit an add-secret request to the Ultravisor (s390x only). Perform an
add-secret request using a previously generated add-secret request. Only
available on s390x.
### Arguments

`<FILE>`
<ul>
Specify the request to be sent.
</ul>



## pvsecret lock
### Synopsis
`pvsecret lock`
### Description
Lock the secret-store (s390x only). Lock the secret store (s390x only). After
this command executed successfully, all subsequent add-secret requests will
fail. Only available on s390x.

## pvsecret list
### Synopsis
`pvsecret list [OPTIONS] [FILE]`
### Description
List all ultravisor secrets (s390x only). Lists the IDs of all non-null secrets
currently stored in the ultravisor for the currently running IBM Secure
Execution guest. Only available on s390x.
### Arguments

`<FILE>`
<ul>
Store the result in FILE.
    Default value: '-'
</ul>


### Options

`--format <FORMAT>`
<ul>
Define the output format of the list.
    Default value: 'human'
    Possible values:
        - **human**: Human-focused, non-parsable output format.
        - **yaml**: Use yaml format.
        - **bin**: Use the format the ultravisor uses to pass the list.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvsecret verify
### Synopsis
`pvsecret verify [OPTIONS] <FILE>`
### Description
Verifies that the given request is an Add-Secret request by testing for some
values to be present. If the request contains signed user-data, the signature
is verified with the provided key. Outputs the arbitrary user-data. All data in
the request is in big endian. `verify` checks the following:

 - The first 6 bytes of the request are equal to: `B6173 7263 624d | asrcbM`
 - The sizes in the request header are sane and do not point out of the file
 - The request version is supported by the binary
 - If user-data contains a signature, verify the signature using a public key

The content of bytes 6&7 of the request define which kind of user-data the
request contains.
 - **0x0000** `no user-data (512 bytes zero)`
 - **0x0001** `512 bytes user-data`
 - **0x0002** `265 bytes user-data| 139 bytes ecdsa signature | 5 bytes reserved
| 2 bytes signature size | ...`
 - **0x0003** `256 bytes user-data | 256 bytes rsa2048 signature`
 - **0x0004** `128 bytes user-data | 384 bytes rsa3072 signature`

The actual user-data may be less than the capacity. If less data was provided
during `create` zeros are appended.
For type 2-4 The signature is calculated as follows:
1) The request is generated with the user-data in place and zeros for the
signature data.
2) The signature is calculated for the request. The signature signs the
authenticated data and the encrypted data, but not the request tag. I.e. the
signature signs the whole request but the last 16 bytes a,d with the signature
bytes set to zero.
3) The signature is inserted to its location in the request.
4) The request GCM tag is calculated.

The verification process works as follows:
1) copy the signature to a buffer
2) overwrite the signature with zeros
3) verify the signature of the request but the last 16 bytes

### Arguments

`<FILE>`
<ul>
Specify the request to be checked.
</ul>


### Options

`--user-cert <FILE>`
<ul>
Certificate containing a public key used to verify the user data signature.
Specifies a public key used to verify the user-data signature. The file must be
a X509 certificate in DSA or PEM format. The certificate must hold the public
EC, RSA 2048, or RSA 3072 key corresponding to the private user-key used during
`create`. No chain of trust is established. Ensuring that the certificate can be
trusted is the responsibility of the user. The EC key must use the NIST/SECG
curve over a 521 bit prime field (secp521r1).
</ul>


`-o`, `--output <FILE>`
<ul>
Store the result in FILE If the request contained abirtary user-data the output
contains this user-data with padded zeros if available.
    Default value: '-'
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>


## pvsecret retrieve
### Synopsis
`pvsecret retrieve [OPTIONS] <ID>`
`pvsecret retr [OPTIONS] <ID>`
### Description
Retrieve a secret from the UV secret store (s390x only)
### Arguments

`<ID>`
<ul>
Specify the secret ID to be retrieved. Input type depends on '--inform'. If
`yaml` (default) is specified, it must be a yaml created by the create
subcommand of this tool. If `hex` is specified, it must be a hex 32-byte
unsigned big endian number string. Leading zeros are required.
</ul>


### Options

`-o`, `--output <FILE>`
<ul>
Specify the output path to place the secret value.
    Default value: '-'
</ul>


`--inform <INFORM>`
<ul>
Define input type for the Secret ID.
    Default value: 'yaml'
    Possible values:
        - **yaml**: Use a yaml file.
        - **hex**: Use a hex string.
        - **name**: Use a name-string. Will hash it if no secret with the name found.
</ul>


`--outform <OUTFORM>`
<ul>
Define the output format for the retrieved secret.
    Default value: 'pem'
    Possible values:
        - **pem**: Write the secret as PEM.
        - **bin**: Write the secret in binary.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>

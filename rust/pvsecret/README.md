<!--
Copyright 2023 IBM Corp.
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
Perform an add-secret request (s390x only)
</ul>

- **lock**
<ul>
Lock the secret-store (s390x only)
</ul>

- **list**
<ul>
List all ultravisor secrets (s390x only)
</ul>

## Options

`-v`, `--verbose`
<ul>
Provide more detailed output
</ul>


`--version`
<ul>
Print version information and exit
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
Use FILE as a certificate to verify the host key or keys. The certificates are
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
Make no attempt to download CRLs
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
created by genprotimg or an extracted IBM Secure Execution header. The header
must start at a page boundary.
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
Write the generated request to FILE
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
must match with the Config-UID from the attestation result of that guest.  If
not specified, the CUID will be ignored by the ultravisor during the
verification of the request.
</ul>


`--cuid <FILE>`
<ul>
Use the content of FILE as the Configuration Unique ID. The file must contain
exactly 128 bit of data or a yaml with a `cuid` entry. If specified, the value
must match the Config-UID from the attestation result of that guest. If not
specified, the CUID will be ignored by the Ultravisor during the verification
of the request.
</ul>


`--flags <FLAGS>`
<ul>
Flags for the add-secret request
    Possible values:
        - **disable-dump**: Disables host-initiated dumping for the target guest instance
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
device to a guest. The `pvapconfig` tool provides more information about
association secrets.
#### Arguments

`<NAME>`
<ul>
String to identify the new secret. The actual secret is set with --input-secret.
The name is saved in `NAME.yaml` with white-spaces mapped to `_`.
</ul>


#### Options

`--stdout`
<ul>
Print the hashed name to stdout. The hashed name is not written to `NAME.yaml`
</ul>


`--input-secret <FILE>`
<ul>
Path from which to read the plaintext secret. Uses a random secret if not
specified
</ul>


`--output-secret <FILE>`
<ul>
Save the generated secret as plaintext in FILE. The generated secret can be used
to generate add-secret requests for a different guest with the same secret using
--input-secret. Destroy the secret when it is not used anymore.
</ul>


## pvsecret add
### Synopsis
`pvsecret add <FILE>`
### Description
Perform an add-secret request (s390x only). Perform an add-secret request using
a previously generated add-secret request. Only available on s390x.
### Arguments

`<FILE>`
<ul>
Specify the request to be sent
</ul>



## pvsecret lock
### Synopsis
`pvsecret lock`
### Description
Lock the secret-store (s390x only). Lock the secret store (s390x only). After
this command executed successfully, all add-secret requests will fail. Only
available on s390x.

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
Store the result in FILE
    Default value: '-'
</ul>


### Options

`--format <FORMAT>`
<ul>
Define the output format of the list
    Default value: 'human'
    Possible values:
        - **human**: Human-focused, non-parsable output format
        - **yaml**: Use yaml format
        - **bin**: Use the format the ultravisor uses to pass the list
</ul>

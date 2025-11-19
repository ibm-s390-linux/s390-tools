<!--Copyright IBM Corp. 2025 -->
# pvverify
## Synopsis
`pvverify [OPTIONS] --host-key-document <FILE> <--no-verify|--cert <FILE>>`
## Description
Tool to verify host-keys Tool to verify host-keys. Use this tool to verify the
chain of trust for IBM Secure
## Options

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


`--version`
<ul>
Print version information and exit.
</ul>


`-h`, `--help`
<ul>
Print help (see a summary with '-h').
</ul>

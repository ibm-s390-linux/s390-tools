# KMIP server profile for IBM-GDE (IBM Security Guardium Data Encryption).

# Regular expression to match the KMIP server information obtained from the
# KMIP server via the QUERY request.
server-regex=Vormetric.*

# KMIP protocol version to use. Either major.minor, or AUTO. AUTO means that
# the supported KMIP protocol version is automatically discovered using the
# DISCOVER VERSIONS request.
kmip-version=2.1

# Transport method for the KMIP protocol: TLS or HTTPS
transport=TLS

# Encoding method for the KMIP protocol: TTLV, JSON or XML.
# JSON and XML are only posisble with HTTPS transport.
encoding=TTLV

# URI used for HTTPS transport. Can be overridden by user via --kmip-server
# option. Ignored if not HTTPS transport.
https-uri=/kmip

# Authentication scheme. Currently only TLS client authentication is supported.
auth-scheme=TLSClientCert

# Key wrapping algorithm for retrieving keys from the KMIP server.
# Currently only RSA is supported.
wrap-key-algorithm=RSA

# For RSA key wrapping: the modulus size of the RSA key: 512, 1024, 2048, 4096
wrap-key-params=4096

# Format used to register the public wrapping key with the KMIP server.
# For RSA: PKCS1, PKCS8, TransparentPublicKey
wrap-key-format=PKCS1

# Padding method used with key wrapping.
# For RSA: PKCS1.5 or OAEP
wrap-padding-method=OAEP

# Hashing algorithm used with key wrapping.
# For RSA with OAEP: SHA-1 or SHA-256
wrap-hashing-algorithm=SHA-1

# KMIP server supports 'Link' attribute. If TRUE, use to link the 2 keys of an
# XTS key together.
supports-link-attr=TRUE

# KMIP server supports 'Description' attribute.
supports-description-attr=TRUE

# KMIP server supports 'Comment' attribute.
supports-comment-attr=TRUE

# Custom/Vendor attribute usage for KMIP v2.x servers.
# V1-style means to set 'Vendor Identifier' to 'x', and 'Attribute Name' to
# 'zkey-<something>'. This coresponds to the KMIP v1.x Custom attribute style.
# V2-style means to set 'Vendor Identifier' to 'zkey', and 'Attribute Name' to
# '<something>'.
custom-attr-scheme=v1-style

# KMIP server supports 'Sensitive' attribute. If TRUE, all keys are generated
# with Sensitive=True to prevent the key from being retrieved in clear.
supports-sensitive-attr=TRUE

# KMIP server supports 'Always Sensitive' attribute and it is checked to be
# True for all keys retrieved by the zkey-kmip plugin.
check-always-sensitive-attr=TRUE

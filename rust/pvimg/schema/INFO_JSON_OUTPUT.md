# pvimg info JSON Output Documentation

This document describes the JSON output format for the `pvimg info` command when
using `--format=json`, `--format=json:minify` or `--format=json:pretty`.

## Overview

The `pvimg info` command outputs information about IBM Secure Execution (SE)
images in JSON format. The output conforms to the JSON schema defined in
[`info-v1.schema.json`](info-v1.schema.json).

## Getting the JSON Schema

To retrieve the JSON schema programmatically, use:

```bash
pvimg info --print-schema json
```

This outputs the complete JSON schema that can be used for validation and
documentation purposes.

## Output Structure

The JSON output has the following top-level structure:

```json
{
  "meta": {
    "api_level": 1,
    "version": "2.x.x",
    "host": "hostname",
    "time_epoch": 1234567890,
    "time": "YYYY-MM-DD HH:MM:SS+ZZZZ"
  },
  "data": {
    // SE header data (see below)
  }
}
```

### Top-Level Fields

- **`meta`** (object, required): Metadata about the s390-tools version and execution environment.
  - **`api_level`** (integer, required): API level version, currently always `1`.
  - **`version`** (string, required): Version of s390-tools.
  - **`host`** (string, required): Hostname where the command was executed.
  - **`time_epoch`** (integer, required): Unix timestamp (seconds since epoch) when the command was executed.
  - **`time`** (string, required): Human-readable timestamp in format 'YYYY-MM-DD HH:MM:SS+ZZZZ'.
- **`data`** (object, required): Contains the Secure Execution header information.

## SE Header Data Types

The `data` object can represent three different states of the SE header:

1. **Decrypted SE Header** (with `--hdr-key` and `--show-secrets`)
2. **Encrypted SE Header (Verified)** (with `--hdr-key`)
3. **Encrypted SE Header (Not Verified)** (without `--hdr-key`)

### Common Fields

All three types share these common fields:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Type of header: `"decrypted_se_hdr"` or `"se_hdr"` |
| `verified` | boolean | Whether the SE header integrity and authenticity verified with the header protection key |
| `magic_hex` | string | Magic number identifying SE header (hex) |
| `version` | string | SE header version (e.g., `"V1"`) |
| `sehs` | integer | SE header size in bytes |
| `iv_hex` | string | Initialization vector (hex) |
| `nks` | integer | Number of key slots |
| `sea` | integer | Encrypted area size in bytes |
| `nep` | integer | Number of (encrypted) component pages |
| `pcf_hex` | string | Plaintext control flags (hex) |
| `cust_pub_key` | object | Customer public key |
| `pld_hex` | string | PLD (Page content List Digest) hash (hex) |
| `ald_hex` | string | ALD (Address List Digest) hash (hex) |
| `tld_hex` | string | TLD (Tweak List Digest) hash (hex) |
| `keyslots` | array | Array of key slot objects |
| `tag_hex` | string | SE header authentication tag (hex) |

#### Customer Public Key Object

```json
{
  "coord_hex": "string"  // EC public key coordinates (hex)
}
```

#### Key Slot Object

```json
{
  "phkh_hex": "string",  // Hash of the public target key (hex)
  "wrpk_hex": "string",  // Wrapped SE header protection key (hex)
  "kst_hex": "string"    // Key slot authentication tag (hex)
}
```

### 1. Decrypted SE Header

When using `--hdr-key` with `--show-secrets`, the output includes decrypted
secrets:

```json
{
  "meta": {
    "api_level": 1,
    "version": "2.x.x",
    "host": "hostname",
    "time_epoch": 1234567890,
    "time": "2026-01-15 10:30:45+0100"
  },
  "data": {
    "kind": "decrypted_se_hdr",
    "verified": true,
    "magic_hex": "49424d5365634578",
    "version": "V1",
    "sehs": 640,
    "iv_hex": "...",
    "nks": 1,
    "sea": 128,
    "nep": 4,
    "pcf_hex": "00000000000000e0",
    "cust_pub_key": {
      "coord_hex": "..."
    },
    "pld_hex": "...",
    "ald_hex": "...",
    "tld_hex": "...",
    "keyslots": [
      {
        "phkh_hex": "...",
        "wrpk_hex": "...",
        "kst_hex": "..."
      }
    ],
    "tag_hex": "...",
    "psw": {
      "mask_hex": "...",
      "addr_hex": "..."
    },
    "scf_hex": "...",
    "cck_hex": "...",
    "xts_hex": "..."
  }
}
```

**Additional fields for decrypted headers:**

| Field | Type | Description |
|-------|------|-------------|
| `psw` | object | Program Status Word with `mask_hex` and `addr_hex` |
| `scf_hex` | string | Secret control flags (hex) |
| `cck_hex` | string | Customer communication key (CCK) (hex) |
| `xts_hex` | string | Components encryption key (hex) |

**Note:** The `cipher_data_b64` field is NOT present in decrypted headers.

### 2. Encrypted SE Header (Verified)

When using `--hdr-key` without `--show-secrets`:

```json
{
  "meta": {
    "api_level": 1,
    "version": "2.x.x",
    "host": "hostname",
    "time_epoch": 1234567890,
    "time": "2026-01-15 10:30:45+0100"
  },
  "data": {
    "kind": "se_hdr",
    "verified": true,
    "magic_hex": "49424d5365634578",
    "version": "V1",
    "sehs": 640,
    "iv_hex": "...",
    "nks": 1,
    "sea": 128,
    "nep": 4,
    "pcf_hex": "00000000000000e0",
    "cust_pub_key": {
      "coord_hex": "..."
    },
    "pld_hex": "...",
    "ald_hex": "...",
    "tld_hex": "...",
    "keyslots": [
      {
        "phkh_hex": "...",
        "wrpk_hex": "...",
        "kst_hex": "..."
      }
    ],
    "tag_hex": "...",
    "cipher_data_b64": "..."
  }
}
```

**Additional field:**

| Field | Type | Description |
|-------|------|-------------|
| `cipher_data_b64` | string | Base64-encoded encrypted header data |

### 3. Encrypted SE Header (Not Verified)

When NOT using `--hdr-key`:

```json
{
  "meta": {
    "api_level": 1,
    "version": "2.x.x",
    "host": "hostname",
    "time_epoch": 1234567890,
    "time": "2026-01-15 10:30:45+0100"
  },
  "data": {
    "kind": "se_hdr",
    "verified": false,
    "magic_hex": "49424d5365634578",
    "version": "V1",
    "sehs": 640,
    "iv_hex": "...",
    "nks": 1,
    "sea": 128,
    "nep": 4,
    "pcf_hex": "00000000000000e0",
    "cust_pub_key": {
      "coord_hex": "..."
    },
    "pld_hex": "...",
    "ald_hex": "...",
    "tld_hex": "...",
    "keyslots": [
      {
        "phkh_hex": "...",
        "wrpk_hex": "...",
        "kst_hex": "..."
      }
    ],
    "tag_hex": "...",
    "cipher_data_b64": "..."
  }
}
```

**Warning:** When `verified` is `false`, the data has NOT been verified and should not be trusted without proper authentication.

## Field Details

### Hex String Format

All fields ending in `_hex` contain hexadecimal strings (characters 0-9, a-f, A-F) without the `0x` prefix.

### Base64 String Format

The `cipher_data_b64` field contains standard Base64-encoded data (characters A-Z, a-z, 0-9, +, /, with optional padding `=`).

### Plaintext Control Flags (PCF)

The `pcf_hex` field is a hexadecimal string representing control flags. These flags control various SE features, e.g.:

- Dumping support
- CCK extension secret requirement
- CCK update support
- PCKMO key encryption functions (DEA, TDEA, AES, ECC)
- PCKMO HMAC support
- Backup target keys support
- Image component encryption

Refer to the IBM Secure Execution documentation for detailed flag meanings.

### Secret Control Flags (SCF)

The `scf_hex` field (only in decrypted headers) contains secret control flags that are encrypted in the SE header.

## Usage Examples

### Basic Info (No Authentication)

```bash
pvimg info se-image.img --format=json
```

Output will have `verified: false` and include `cipher_data_b64`.

### Verified Info

```bash
pvimg info se-image.img --format=json --hdr-key header.key
```

Output will have `verified: true` and include `cipher_data_b64`.

### Decrypted Info with Secrets

```bash
pvimg info se-image.img --format=json --hdr-key header.key --show-secrets
```

Output will have `verified: true`, `kind: "decrypted_se_hdr"`, and include decrypted fields (`psw`, `scf_hex`, `cck_hex`, `xts_hex`) instead of `cipher_data_b64`.

### Pretty-Printed JSON

```bash
pvimg info se-image.img --format=json:pretty --hdr-key header.key
```

Outputs formatted JSON with indentation for better readability.

### Get JSON Schema

```bash
pvimg info --print-schema json > info-schema.json
```

Saves the JSON schema to a file for validation purposes.

## Validation

The output can be validated against the JSON schema using standard JSON schema validators:

```bash
# Get the schema
pvimg info --print-schema json > schema.json

# Generate output
pvimg info se-image.img --format=json > output.json

# Validate (using a JSON schema validator tool)
check-jsonschema -i output.json schema.json
```

## Security Considerations

1. **Verification Required**: Always use `--hdr-key` to verify the SE header authenticity. Without verification (`verified: false`), the data cannot be trusted.

2. **Secrets Protection**: The `--show-secrets` option exposes sensitive cryptographic material. Only use this option in secure environments and never share the output containing secrets.

3. **Key Protection**: The header key file specified with `--hdr-key` must be kept secure. It was used for the image creation with `pvimg create --hdr-key <HDR_KEY>`.

## Version History

- **API Level 1**: Initial JSON output format for SE header V1

## See Also

- [`info-v1.schema.json`](info-v1.schema.json) - JSON Schema definition
- `pvimg info --help` - Command-line help
- `man pvimg-info` - Manual page
- IBM Secure Execution documentation

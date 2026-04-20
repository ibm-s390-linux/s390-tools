// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::fmt::{Debug, Display};
use std::time::Duration;

use anyhow::{bail, Result};
use base64::prelude::*;
use curl::easy::{Easy2, Handler, List, WriteError};
use log::{debug, info, log_enabled};
use serde::{Deserialize, Serialize};

use super::{bail_check, CheckState};
use crate::additional::AttestationResult;
use crate::cli::CheckOpt;

const CHECK_DEFAULT_ENDP: &str = "https://esupport.ibm.com/eccedge/ent/z";
const TIMEOUT_MAX: Duration = Duration::from_secs(3);
const USER_AGENT: &str = "s390-tools-pvattest";
const CONTENT_TYPE: &str = "Content-Type: application/json";
const CLIENT_ID: &str = "x-client-id: X";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum Version {
    #[serde(rename = "1.0")]
    V1,
    #[serde(rename = "2.0")]
    V2,
}

trait Request: Serialize + Debug {
    type Response: Response;

    fn new(firmware_hash: &[u8]) -> Self;
}

#[derive(Debug, Serialize, Deserialize)]
struct RequestV1_1 {
    version: Version,
    payload: String,
}

impl Request for RequestV1_1 {
    type Response = ResponseV1;

    fn new(firmware_hash: &[u8]) -> Self {
        Self {
            version: Version::V1,
            payload: BASE64_STANDARD.encode(firmware_hash),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RequestV1_2 {
    version: Version,
    payload: String,
}

impl Request for RequestV1_2 {
    type Response = ResponseV2;

    fn new(firmware_hash: &[u8]) -> Self {
        Self {
            version: Version::V1,
            payload: BASE64_STANDARD.encode(firmware_hash),
        }
    }
}

/// Trait for firmware verification response types.
///
/// This trait defines the interface for handling responses from the IBM firmware
/// verification API.
trait Response: serde::de::DeserializeOwned + Debug + Display {
    /// The API version constant for this response type.
    const VERSION: Version;

    /// Returns whether the firmware verification was successful.
    ///
    /// # Returns
    ///
    /// `true` if the firmware is in a valid state, `false` otherwise.
    fn valid(&self) -> bool;

    /// Constructs the verification API endpoint URL for this response version.
    ///
    /// * `endp` - The base endpoint URL (e.g., "<https://esupport.ibm.com/eccedge/ent/z>")
    ///
    /// # Returns
    ///
    /// The complete API endpoint URL for firmware verification, including the version path.
    fn verify_api(endp: &str) -> String {
        let ver = match Self::VERSION {
            Version::V1 => "v1",
            Version::V2 => "v2",
        };
        format!("{endp}/hmrs/firmware/attestation/{ver}/verify",)
    }
}

// allow unused because all fields are provided by the REST API but may be unused by this toolk
#[allow(unused)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseV1 {
    version: Version,
    valid: bool,
    reference_id: String,
    #[serde(default)]
    reason: Option<String>,
}

impl Response for ResponseV1 {
    const VERSION: Version = Version::V1;
    fn valid(&self) -> bool {
        self.valid
    }
}

impl Display for ResponseV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The firmware is {}in a valid state",
            if self.valid { "" } else { "not " }
        )?;

        self.reason.as_ref().map_or(Ok(()), |r| {
            write!(f, "\n  Reason: {r}\n  ReferenceId: {}", self.reference_id)
        })
    }
}

// allow unused because all fields are provided by the REST API but may be unused by this toolk
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedHashV2 {
    hash: String,
    signature: String,
}

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseV2 {
    version: Version,
    valid: bool,
    reason: String,
    verified_hashes: Vec<VerifiedHashV2>,
}

impl Response for ResponseV2 {
    const VERSION: Version = Version::V2;
    fn valid(&self) -> bool {
        self.valid
    }
}

impl Display for ResponseV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "The firmware is {}in a valid state",
            if self.valid { "" } else { "not " }
        )?;
        let json = serde_json::to_string_pretty(self).map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

#[derive(Debug)]
struct Buf(Vec<u8>);
impl Handler for Buf {
    fn write(&mut self, data: &[u8]) -> std::result::Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}

fn check<Q, U>(fw_hash: &U, endp: &str) -> Result<CheckState<()>>
where
    Q: Request,
    U: AsRef<[u8]>,
{
    let req = serde_json::to_vec(&Q::new(fw_hash.as_ref()))?;

    let url = Q::Response::verify_api(endp);
    debug!("POST {url}");

    let mut http_header = List::new();
    http_header.append(CLIENT_ID)?;
    http_header.append(CONTENT_TYPE)?;

    let mut handle = Easy2::new(Buf(Vec::with_capacity(0x1000)));
    handle.buffer_size(102400)?;
    handle.url(&url)?;
    handle.post_fields_copy(&req)?;
    handle.http_headers(http_header)?;
    handle.useragent(USER_AGENT)?;
    handle.max_redirections(50)?;
    handle.post(true)?;
    handle.timeout(TIMEOUT_MAX)?;
    handle.follow_location(true)?;
    if log_enabled!(log::Level::Trace) {
        handle.verbose(true)?;
    }
    handle.perform()?;

    if handle.response_code()? != 200 {
        bail!(
            "The firmware verification server responded with http response status code '{}'",
            handle.response_code()?
        );
    }

    let resp: Q::Response = match serde_json::from_slice(&handle.get_ref().0) {
        Ok(res) => res,
        Err(e) => bail!(
            "Unexpected response from server: {} \n (\"{}\")",
            String::from_utf8(handle.get_ref().0.clone())
                .unwrap_or_else(|_| "No UTF-8 message".to_string()),
            e
        ),
    };

    debug!("Firmware check {resp:?}");

    match resp.valid() {
        true => info!("✓ {resp}"),
        false => bail_check!(&format!("{resp}")),
    }

    Ok(CheckState::Data(()))
}

fn firmware_check<Q>(opt: &CheckOpt, att_res: &AttestationResult) -> Result<CheckState<()>>
where
    Q: Request,
{
    if !opt.firmware {
        return Ok(None.into());
    }

    let endp = opt
        .firmware_verify_url
        .as_deref()
        .unwrap_or(CHECK_DEFAULT_ENDP);

    match att_res
        .add_fields
        .as_ref()
        .and_then(|add| add.firmware_state())
    {
        Some(hash) => check::<Q, _>(hash, endp),
        None => {
            bail_check!(
                "The Attestation response contains no firmware hash, but checking was enabled"
            )
        }
    }
}

pub fn firmware_check_v1(opt: &CheckOpt, att_res: &AttestationResult) -> Result<CheckState<()>> {
    firmware_check::<RequestV1_1>(opt, att_res)
}

pub fn firmware_check_v2(opt: &CheckOpt, att_res: &AttestationResult) -> Result<CheckState<()>> {
    firmware_check::<RequestV1_2>(opt, att_res)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_request_v1_1() {
        let payload = BASE64_STANDARD.encode([42u8; 320]);
        let req = RequestV1_1::new(&[42u8; 320]);

        assert!(matches!(req.version, Version::V1));
        assert_eq!(req.payload, payload);

        let json = serde_json::to_string(&req).unwrap();
        let expected = format!(r#"{{"version":"1.0","payload":"{payload}"}}"#);
        assert_eq!(json, expected);
    }

    #[test]
    fn serialize_request_v1_2() {
        let payload = BASE64_STANDARD.encode([42u8; 320]);
        let req = RequestV1_2::new(&[42u8; 320]);

        assert!(matches!(req.version, Version::V1));
        assert_eq!(req.payload, payload);

        let json = serde_json::to_string(&req).unwrap();
        let expected = format!(r#"{{"version":"1.0","payload":"{payload}"}}"#);
        assert_eq!(json, expected);
    }

    #[test]
    fn parse_response_v1() {
        let json = r#"{
  "version": "1.0",
  "valid": true,
  "referenceId": "ref-1",
  "reason": "string"
}"#;

        let resp: ResponseV1 = serde_json::from_str(json).unwrap();
        assert!(resp.valid());
        assert!(matches!(resp.version, Version::V1));
        assert_eq!(resp.reference_id, "ref-1");
        assert_eq!(resp.reason.as_deref(), Some("string"));

        let display = resp.to_string();
        let expected = "The firmware is in a valid state\n  Reason: string\n  ReferenceId: ref-1";
        assert_eq!(display, expected);
    }

    #[test]
    fn parse_response_v1_without_reason() {
        let json = r#"{
  "version": "1.0",
  "valid": true,
  "referenceId": "ref-1"
}"#;

        let resp: ResponseV1 = serde_json::from_str(json).unwrap();
        assert!(resp.valid());
        assert!(matches!(resp.version, Version::V1));
        assert_eq!(resp.reference_id, "ref-1");
        assert_eq!(resp.reason, None);

        let display = resp.to_string();
        let expected = "The firmware is in a valid state";
        assert_eq!(display, expected);
    }

    #[test]
    fn parse_response_v2() {
        let verified_hashes: Vec<_> = (0u8..4)
            .map(|i| {
                (
                    BASE64_STANDARD.encode([42u8 + i; 256]),
                    BASE64_STANDARD.encode([17u8 + i; 256]),
                )
            })
            .collect();

        let json = format!(
            r#"{{
  "version": "2.0",
  "valid": true,
  "reason": "string",
  "verifiedHashes": [
    {{
      "hash": "{}",
      "signature": "{}"
    }},
    {{
      "hash": "{}",
      "signature": "{}"
    }},
    {{
      "hash": "{}",
      "signature": "{}"
    }},
    {{
      "hash": "{}",
      "signature": "{}"
    }}
  ]
}}"#,
            verified_hashes[0].0,
            verified_hashes[0].1,
            verified_hashes[1].0,
            verified_hashes[1].1,
            verified_hashes[2].0,
            verified_hashes[2].1,
            verified_hashes[3].0,
            verified_hashes[3].1,
        );

        let resp: ResponseV2 = serde_json::from_str(&json).unwrap();
        assert!(resp.valid());
        assert!(matches!(resp.version, Version::V2));
        assert_eq!(resp.reason, "string");
        assert_eq!(resp.verified_hashes.len(), 4);

        for (verified_hash, (hash, signature)) in
            resp.verified_hashes.iter().zip(verified_hashes.iter())
        {
            assert_eq!(&verified_hash.hash, hash);
            assert_eq!(&verified_hash.signature, signature);
        }

        let display = resp.to_string();
        let expected = format!("The firmware is in a valid state\n{json}");
        assert_eq!(display, expected);
    }
}

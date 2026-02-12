use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::gethostname;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct S390ToolsMetaData {
    pub api_level: u32,
    pub version: String,
    pub host: String,
    pub time_epoch: u64,
    pub time: String,
}

impl S390ToolsMetaData {
    /// Creates a new S390ToolsMetaData with current system information
    ///
    /// # Arguments
    ///
    /// * `api_level` - The API level version to use
    pub fn new(api_level: u32) -> Self {
        let host = gethostname().unwrap_or("unknown".to_owned());
        let version = crate::release_string!().to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch");
        let time_epoch = now.as_secs();
        let dt = DateTime::<Utc>::from(UNIX_EPOCH + now);
        let time = dt.format("%F %T%z").to_string();

        Self {
            api_level,
            version,
            host,
            time_epoch,
            time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = S390ToolsMetaData::new(1);
        assert_eq!(metadata.api_level, 1);
        assert!(!metadata.version.is_empty());
        assert!(!metadata.host.is_empty());
        assert!(metadata.time_epoch > 0);
        assert!(!metadata.time.is_empty());
    }

    #[test]
    fn test_metadata_serialization_deserialization() {
        let metadata = S390ToolsMetaData {
            api_level: 1,
            version: "DEBUG_BUILD".to_string(),
            host: "testhost".to_string(),
            time_epoch: 1770912807,
            time: "2026-02-12 16:13:27+0000".to_string(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert_eq!(
            json,
            r#"{"api_level":1,"version":"DEBUG_BUILD","host":"testhost","time_epoch":1770912807,"time":"2026-02-12 16:13:27+0000"}"#
        );
        let deserialized: S390ToolsMetaData = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata, deserialized);
    }
}

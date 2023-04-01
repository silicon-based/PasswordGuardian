use crate::error::DataStorageError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// metadata.json:
/// 1. salts: salt for deriving kek.
/// 2. wrap: `AES-KW(enc_key, kek)`
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    salts: [String; 1],
    wrap: String,
}

impl Metadata {
    pub fn from_file(path: &Path) -> Result<Self, DataStorageError> {
        if !path.exists() {
            return Err(DataStorageError::FileNotFound {
                path: path.to_path_buf(),
            });
        }
        let data = fs::read_to_string(path).unwrap();
        let x: Metadata =
            serde_json::from_str(&data).map_err(|_| DataStorageError::MetadataCorrupted {
                cause: "file is not a propper json object metadata.".into(),
            })?;
        Ok(x)
    }

    pub fn new(wrap: String, salts: [String; 1]) -> Self {
        Self { wrap, salts }
    }
    pub fn wrap(&self) -> Result<[u8; 40], DataStorageError> {
        base64_url::decode(&self.wrap)
            .map_err(|_| DataStorageError::MetadataCorrupted {
                cause: "data value is tampered.".into(),
            })?
            .try_into()
            .map_err(|_| DataStorageError::MetadataCorrupted {
                cause: "data value is tampered.".into(),
            })
    }
    pub fn kek_salt(&self) -> Result<Vec<u8>, DataStorageError> {
        base64_url::decode(&self.salts[0]).map_err(|_| DataStorageError::MetadataCorrupted {
            cause: "data value is tampered.".into(),
        })
    }
    pub fn write_metadata(&self, path: &Path) -> Result<(), DataStorageError> {
        if !path.exists() {
            return Err(DataStorageError::FileNotFound {
                path: path.to_path_buf(),
            });
        }
        let j = serde_json::to_string(&self).unwrap();
        fs::write(path, j).unwrap();
        Ok(())
    }
}

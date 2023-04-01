use std::{error::Error, fmt::Display, path::PathBuf};

#[derive(Debug)]
pub enum DataStorageError {
    FileNotFound { path: PathBuf },
    MetadataCorrupted { cause: String },
    DatabaseError { cause: rusqlite::Error },
}

impl From<rusqlite::Error> for DataStorageError {
    fn from(value: rusqlite::Error) -> Self {
        DataStorageError::DatabaseError { cause: value }
    }
}

impl Display for DataStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataStorageError::FileNotFound { path } => {
                write!(f, "Failed to locate such file: {}", path.display())
            }
            DataStorageError::MetadataCorrupted { cause: source } => {
                write!(
                    f,
                    "Unable to read metadata because metadata file is corrupted: {}",
                    source
                )
            }
            DataStorageError::DatabaseError { cause } => {
                write!(
                    f,
                    "Failed when executing database operation. Detail: {}",
                    cause
                )
            }
        }
    }
}

impl Error for DataStorageError {}

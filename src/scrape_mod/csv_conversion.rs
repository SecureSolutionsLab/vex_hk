use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::osv_schema::{OsvEssentials, OSV};

#[derive(thiserror::Error, Debug)]
pub enum CsvCreationError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Failed to serialize data to json:\n{0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Failed to read zip archive: {0}")]
    ZipArchiveReading(#[from] zip::result::ZipError),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvCsvRow {
    pub id: String,
    published: String,
    modified: String,
    json: String,
}

impl OsvCsvRow {
    pub fn as_row<'a>(&'a self) -> [&'a str; 4] {
        [&self.id, &self.published, &self.modified, &self.json]
    }

    pub fn from_osv<T: Serialize>(data: OSV<T>) -> Self {
        let id = data.id.clone();
        let published = data.published.unwrap_or(data.modified).to_rfc3339();
        let modified = data.modified.to_rfc3339();
        let json = serde_json::json!(data).to_string();
        Self {
            id,
            published,
            modified,
            json,
        }
    }

    pub fn from_csv_record(record: csv::StringRecord) -> Self {
        record
            .deserialize(None)
            .expect("Failed to convert csv record to row struct")
    }

    pub fn to_essentials(self) -> OsvEssentials {
        OsvEssentials::new(
            self.id,
            DateTime::parse_from_rfc3339(&self.published)
                .expect("Invalid OsvCsvRow published date")
                .to_utc(),
            DateTime::parse_from_rfc3339(&self.modified)
                .expect("Invalid OsvCsvRow modified date")
                .to_utc(),
        )
    }
}

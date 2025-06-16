//! # Functionality to make it easier to store arbitrary data to a database
//!
//! Conversion to CSV and communication with the database

use std::{path::Path, time::Instant};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolCopyExt;

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

/// Generalized row information to be set to a database
///
/// Stores id, published and modified information, together with arbitrary json as strings, for serialization/deserialization purposes.
/// This is to be used with json data that is meant to be stored whole in the database itself, instead of in a more relational or columnwise approach.
// todo: implement a more meaningful Debug
#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralizedCsvRecord {
    pub id: String,
    published: String,
    modified: String,
    json: String,
}

impl GeneralizedCsvRecord {
    /// Represent data in a row of [id, published, modified, json]
    ///
    /// This can be used directly as a record by the csv library
    pub fn as_row<'a>(&'a self) -> [&'a str; 4] {
        [&self.id, &self.published, &self.modified, &self.json]
    }

    /// Serialize data from OSV. The whole OSV is stored in the json field.
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

    /// Parse data from an existing arbitrary CSV record. This function will panic if the format is invalid.
    pub fn from_csv_record(record: csv::StringRecord) -> Self {
        record
            .deserialize(None)
            .expect("Failed to convert csv record to row struct")
    }

    /// Serialize data to essentials for comparing advisories
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

/// Read CSV and send data **as is** to Postgres. This does not perform any checks, other by forwarding errors returned by Postgres itself.
///
/// This does NOT replace data, only inserts it.
pub async fn send_csv_to_database_whole(
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
    expected_rows_count: usize,
) -> Result<(), sqlx::Error> {
    log::info!(
        "Opening {:?} and sending whole to database, table name: {}",
        file_path,
        table_name
    );
    let processing_start = Instant::now();
    let mut copy_conn = db_connection
        .copy_in_raw(&format!(
            "COPY \"{}\" FROM STDIN (FORMAT csv, DELIMITER ',')",
            table_name
        ))
        .await?;

    let file = tokio::fs::File::open(file_path).await?;

    copy_conn.read_from(file).await?;

    let result = copy_conn.finish().await?;
    assert_eq!(result as usize, expected_rows_count);

    log::info!("Finished sending CSV in {:?}", processing_start.elapsed());

    Ok(())
}

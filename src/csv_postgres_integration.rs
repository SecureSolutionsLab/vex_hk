//! # Functionality for storing and sending arbitrary data to a database
//!
//! Conversion to CSV and communication with the database
//!
//! All database tables that use this module are to be created in this format:
//!
//! ```text
//! \"id\" <Format depended string format for ids> PRIMARY KEY,
//! \"published\" TIMESTAMPTZ NOT NULL,
//! \"modified\" TIMESTAMPTZ NOT NULL,
//! \"data\" JSONB NOT NULL
//! ```
//!
//! Data is an arbitrary JSON object depended on the database format used. This would be OSV, for example, for data that exists in OSV format.

use std::{path::Path, time::Instant};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolCopyExt, Execute, Executor, Postgres, QueryBuilder};

use crate::{default_config, osv_schema::OSV};

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

pub fn format_sql_create_table_command(table_name: &str, id_sql_type: &str) -> String {
    format!(
        "CREATE TABLE \"{}\" (
            \"id\" {} PRIMARY KEY,
            \"published\" TIMESTAMPTZ NOT NULL,
            \"modified\" TIMESTAMPTZ NOT NULL,
            \"data\" JSONB NOT NULL
        );",
        table_name, id_sql_type
    )
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

    pub fn from_github_api_response(
        data: crate::scrape_mod::github::api_response::GitHubAdvisoryAPIResponse,
    ) -> Self {
        let id = data.ghsa_id.clone();
        let published = data.published_at.to_rfc3339();
        let modified = data.updated_at.to_rfc3339();
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
}

/// Read CSV and send data **as is** to Postgres. This does not perform any checks, other by forwarding errors returned by Postgres itself.
///
/// This does NOT replace data, only inserts it. It will return an error on conflict.
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

async fn update_with_temp_table(
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
    mut insert_query: sqlx::QueryBuilder<'_, sqlx::Postgres>,
) -> Result<u64, sqlx::Error> {
    log::info!(
        "Opening {:?} and updating database, table name: {}. Inserting new entries and updating old ones.",
        file_path,
        table_name
    );
    let processing_start = Instant::now();

    // rollback is called if this functions exits early on error
    let mut tx = db_connection.begin().await?;
    // if sqlx updates in the future, they will probably change this, but this is how it's in the
    // main docs, as of writing
    let tx_conn = &mut *tx;

    // create new temp table
    log::debug!("Transaction: creating temporary table");
    tx_conn
        .execute(
            QueryBuilder::<Postgres>::new(format!(
                "
CREATE TEMP TABLE \"{}\" 
(LIKE \"{}\" INCLUDING DEFAULTS)
ON COMMIT DROP;
        ",
                default_config::TEMP_TABLE_NAME,
                table_name
            ))
            .build()
            .sql(),
        )
        .await?;

    // copy to temp table
    log::debug!("Transaction: copying stdin data to temp table");
    {
        let mut copy_conn = tx_conn
            .copy_in_raw(&format!(
                "COPY \"{}\" FROM STDIN (FORMAT csv, DELIMITER ',')",
                default_config::TEMP_TABLE_NAME
            ))
            .await?;
        let file = tokio::fs::File::open(file_path).await?;
        copy_conn.read_from(file).await?;

        let result = copy_conn.finish().await?;
        log::debug!("CSV update copy connection result: {}", result);
    }

    // copy from temp to real table
    log::debug!("Transaction: copying data from temp table and updating");
    let result = tx_conn.execute(insert_query.build().sql()).await?;
    let affected_rows = result.rows_affected();
    log::debug!(
        "Transaction insert from temp, {} affected rows",
        affected_rows
    );

    log::debug!("Transaction: Attempting to commit");
    tx.commit().await?;

    log::info!(
        "Finished updating CSV in {:?}, {} affected rows",
        processing_start.elapsed(),
        affected_rows
    );

    Ok(affected_rows)
}

/// Read CSV and send data to Postgres. This does not perform any checks, other by forwarding errors returned by Postgres itself.
///
/// This function DOES replace data, newer entries replacing older ones, regardless of published/modified date.
///
/// Returns number of affected rows
pub async fn insert_and_replace_any_in_database_from_csv(
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
) -> Result<u64, sqlx::Error> {
    update_with_temp_table(
        db_connection,
        file_path,
        table_name,
        QueryBuilder::<Postgres>::new(format!(
            "
INSERT INTO \"{}\" (id, published, modified, data)
SELECT *
FROM \"{}\"
ON CONFLICT (id) DO UPDATE 
    SET published = excluded.published,
        modified  = excluded.modified,
        data      = excluded.data;
        ",
            table_name,
            default_config::TEMP_TABLE_NAME
        )),
    )
    .await
}

/// Read CSV and send data to Postgres. This does not perform any checks, other by forwarding errors returned by Postgres itself.
///
/// This function DOES replace data, newer entries replacing older ones IF modified date is higher than the previous one.
///
/// Returns number of affected rows
pub async fn insert_and_replace_older_entries_in_database_from_csv(
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
) -> Result<u64, sqlx::Error> {
    update_with_temp_table(
        db_connection,
        file_path,
        table_name,
        QueryBuilder::<Postgres>::new(format!(
            "
INSERT INTO \"{}\" AS orig (id, published, modified, data)
SELECT *
FROM \"{}\"
ON CONFLICT (id) DO UPDATE 
    SET published = excluded.published,
        modified  = excluded.modified,
        data      = excluded.data
            WHERE orig.modified < excluded.modified;
        ",
            table_name,
            default_config::TEMP_TABLE_NAME
        )),
    )
    .await
}

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

use serde::{Deserialize, Serialize};
use sqlx::{Execute, Executor, Postgres, QueryBuilder};

use crate::{db_api, default_config, osv_schema::OSV};

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
        "CREATE TABLE \"{table_name}\" (
            \"id\" {id_sql_type} PRIMARY KEY,
            \"published\" TIMESTAMPTZ NOT NULL,
            \"modified\" TIMESTAMPTZ NOT NULL,
            \"data\" JSONB NOT NULL
        );"
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
    pub fn as_row(&self) -> [&str; 4] {
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
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
    expected_rows_count: usize,
) -> Result<(), sqlx::Error> {
    log::info!(
        "Opening {file_path:?} and sending whole to database, table name: {table_name}"
    );
    let processing_start = Instant::now();
    let mut conn = db_pool.acquire().await?;
    let result =
        db_api::copy::execute_read_file_and_copy_to_table(&mut conn, table_name, file_path).await?;
    assert_eq!(result as usize, expected_rows_count);

    log::info!("Finished sending CSV in {:?}", processing_start.elapsed());

    Ok(())
}

async fn update_with_temp_table(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
    mut insert_query: sqlx::QueryBuilder<'_, sqlx::Postgres>,
) -> Result<u64, sqlx::Error> {
    log::info!(
        "Opening {file_path:?} and updating database, table name: {table_name}. Inserting new entries and updating old ones."
    );
    let processing_start = Instant::now();

    // rollback is called if this functions exits early on error
    let mut tx = db_pool.begin().await?;
    // if sqlx updates in the future, they will probably change this, but this is how it's in the
    // main docs, as of writing
    let tx_conn = &mut *tx;

    log::debug!("Transaction: creating temporary table");
    db_api::create::execute_create_tmp_table_drop_on_commit(
        tx_conn,
        default_config::TEMP_TABLE_NAME,
        table_name,
    )
    .await?;

    log::debug!("Transaction: copying stdin data to temp table");
    db_api::copy::execute_read_file_and_copy_to_table(
        tx_conn,
        default_config::TEMP_TABLE_NAME,
        file_path,
    )
    .await?;

    // copy from temp to real table
    log::debug!("Transaction: copying data from temp table and updating");
    let result = tx_conn.execute(insert_query.build().sql()).await?;
    let affected_rows = result.rows_affected();
    log::debug!(
        "Transaction insert from temp, {affected_rows} affected rows"
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

fn replace_entries_query(to_table: &str, from_table: &str) -> String {
    format!(
        "
INSERT INTO \"{to_table}\" (id, published, modified, data)
SELECT *
FROM \"{from_table}\"
ON CONFLICT (id) DO UPDATE 
    SET published = excluded.published,
        modified  = excluded.modified,
        data      = excluded.data;
        "
    )
}

/// Read CSV and send data to Postgres. This does not perform any checks, other by forwarding errors returned by Postgres itself.
///
/// This function DOES replace data, newer entries replacing older ones, regardless of published/modified date.
///
/// Returns number of affected rows
pub async fn insert_and_replace_any_in_database_from_csv(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
) -> Result<u64, sqlx::Error> {
    update_with_temp_table(
        db_pool,
        file_path,
        table_name,
        QueryBuilder::<Postgres>::new(replace_entries_query(
            table_name,
            default_config::TEMP_TABLE_NAME,
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
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    file_path: &Path,
    table_name: &str,
) -> Result<u64, sqlx::Error> {
    update_with_temp_table(
        db_pool,
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

pub async fn add_new_update_and_delete(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    new_entries_file_path: &Path,
    to_update_entries_file_path: &Path,
    to_delete_entries: &[&str],
    table_name: &str,
) -> Result<u64, sqlx::Error> {
    log::info!(
        "Adding, updating and deleting entries in database, table name: {table_name}. New entries file: {new_entries_file_path:?}. Update entries file: {to_update_entries_file_path:?}"
    );
    let processing_start = Instant::now();

    // rollback is called if this functions exits early on error
    let mut tx = db_pool.begin().await?;
    // if sqlx updates in the future, they will probably change this, but this is how it's in the
    // main docs, as of writing
    let tx_conn = &mut *tx;

    let deleted_rows =
        db_api::delete::execute_delete_entries_by_id_slow(tx_conn, table_name, to_delete_entries)
            .await?;
    assert_eq!(deleted_rows, to_delete_entries.len());
    db_api::create::execute_create_tmp_table_drop_on_commit(
        tx_conn,
        default_config::TEMP_TABLE_NAME,
        table_name,
    ).await?;
    // both files should not contain duplicated entries
    db_api::copy::execute_read_file_and_copy_to_table(
        tx_conn,
        default_config::TEMP_TABLE_NAME,
        new_entries_file_path,
    ).await?;
    db_api::copy::execute_read_file_and_copy_to_table(
        tx_conn,
        default_config::TEMP_TABLE_NAME,
        to_update_entries_file_path,
    ).await?;

    log::debug!("Transaction: copying data from temp table and updating");
    let query_str = replace_entries_query(table_name, default_config::TEMP_TABLE_NAME);
    let result = tx_conn.execute(sqlx::query(&query_str)).await?;
    let affected_rows = result.rows_affected();
    log::debug!(
        "Transaction insert from temp, {affected_rows} affected rows"
    );

    log::debug!("Transaction: Attempting to commit");
    tx.commit().await?;

    log::info!(
        "Finished updating CSV in {:?}, {} deleted rows, {} inserted or updated rows",
        processing_start.elapsed(),
        deleted_rows,
        affected_rows
    );

    Ok(affected_rows)
}

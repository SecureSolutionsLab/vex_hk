use std::{fs, path::Path, time::Instant};

use crate::download::download_and_save_to_file_in_chunks;

const FULL_DATA_URL: &str = "https://github.com/github/advisory-database/archive/refs/heads/main.zip";
const TEMP_FILE_PATH: &str = "./temp/github_all_temp.zip";

pub async fn download_full(
    client: reqwest::Client,
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    //log::info!("Creating a new OSV table with name \"{OSV_TABLE_NAME}\" and data column \"{OSV_DATA_COLUMN_NAME}\"");

    // db_connection
    // .execute(QueryBuilder::<Postgres>::new(format!(
    //     "DROP TABLE IF EXISTS \"{OSV_TABLE_NAME}\";
    //      CREATE TABLE \"{OSV_TABLE_NAME}\" (\"id\" INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, \"{OSV_DATA_COLUMN_NAME}\" JSONB NOT NULL);",
    // )).build().sql())
    // .await
    // .unwrap();

    log::info!("Starting full github advisories download.");

    download_and_save_to_file_in_chunks(client, FULL_DATA_URL, Path::new(TEMP_FILE_PATH), &pg_bars).await?;
    // read_file_and_send_to_database(TEMP_FILE_PATH, db_connection, pg_bars).await?;
    // update_osv_timestamp()?;

    log::info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );

    fs::remove_file(TEMP_FILE_PATH)?;
    Ok(())
}
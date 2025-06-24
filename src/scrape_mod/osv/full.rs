use chrono::Utc;
use sqlx::{Execute, Executor, Postgres, QueryBuilder};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};
use zip::ZipArchive;

use super::{OSV_ID_MAX_CHARACTERS, OSV_ID_SQL_TYPE, TEMP_CSV_FILE_NAME, TEMP_DOWNLOAD_FILE_NAME};
use crate::{
    config::Config,
    csv_postgres_integration::{self, GeneralizedCsvRecord},
    download::download_and_save_to_file_in_chunks,
    osv_schema::OSVGeneralized,
    state::ScraperState,
};

const FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE: usize = 42_000_000; // 42mb

/// See [scrape_osv_full] for more information
///
/// This function saves scraper state
pub async fn manual_download_and_save_state(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    state: &mut ScraperState,
) -> anyhow::Result<()> {
    let start_time = Utc::now();
    scrape_osv_full(config, client, db_connection, pg_bars, true).await?;
    state.save_osv(config, start_time);
    Ok(())
}

/// Downloads whole OSV ZIP archive data and stores all separate records to a database.
/// A OSV timestamp is then created to aid in future partial updates.
///
/// Modes of operation:
///
///  - recreate_database_table set to true: Recreate and completely repopulate the table.
///  - recreate_database_table set to false: Try to update existing data by inserting or replacing old values with newer ones. This won't delete entries if they for some reason disappear from the full data. This won't create the table if it doesn't exist. This won't check for any previously corrupted data.
pub async fn scrape_osv_full(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    recreate_database_table: bool,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let osv_status = &config.osv;

    log::info!("Starting full OSV database download.");

    let download_path = config.temp_dir_path.join(TEMP_DOWNLOAD_FILE_NAME);
    let csv_path = config.temp_dir_path.join(TEMP_CSV_FILE_NAME);

    download_and_save_to_file_in_chunks(
        client,
        &osv_status.full_data_url,
        &download_path,
        pg_bars,
    )
    .await?;

    let row_count = create_csv(&download_path, &csv_path, pg_bars).await?;

    if recreate_database_table {
        log::info!("Recreating database table.");
        let database_delete_start = Instant::now();
        db_connection
            .execute(
                QueryBuilder::<Postgres>::new(format!(
                    "DROP TABLE IF EXISTS \"{}\";\n{}",
                    osv_status.table_name,
                    csv_postgres_integration::format_sql_create_table_command(
                        &osv_status.table_name,
                        OSV_ID_SQL_TYPE
                    )
                ))
                .build()
                .sql(),
            )
            .await
            .unwrap();
        log::info!(
            "Creating a new OSV table with name \"{}\"",
            osv_status.table_name
        );
        log::info!(
            "Finished recreating database table. Time: {:?}",
            database_delete_start.elapsed()
        );

        csv_postgres_integration::send_csv_to_database_whole(
            db_connection,
            &csv_path,
            &osv_status.table_name,
            row_count,
        )
        .await?;
    } else {
        log::info!(
            "Attempting an update on the existing table. Number of entries: {row_count}",
        );

        csv_postgres_integration::insert_and_replace_older_entries_in_database_from_csv(
            db_connection,
            &csv_path,
            &osv_status.table_name,
        )
        .await?;
    }

    log::info!("Removing temporary files.");
    fs::remove_file(&csv_path)?;
    fs::remove_file(&download_path)?;

    log::info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );
    Ok(())
}

pub async fn create_csv(
    download: &Path,
    csv: &Path,
    pg_bars: &indicatif::MultiProgress,
) -> anyhow::Result<usize> {
    let processing_start = Instant::now();

    let download_file = File::open(download)?;
    let mut archive = ZipArchive::new(download_file)?;

    log::info!(
        "About to process and convert {} files to csv. File created at {:?}",
        archive.len(),
        csv
    );

    let bar = pg_bars.add(indicatif::ProgressBar::new(archive.len() as u64));

    let parent = csv.parent().unwrap();
    if !fs::exists(parent)? {
        fs::create_dir_all(parent)?;
    }
    let mut csv_writer = csv::WriterBuilder::new()
        .buffer_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE)
        .has_headers(false)
        .from_path(csv)?;

    let mut buffer: String = String::with_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE);
    let mut processed_file_count = 0;
    for file_i in 0..archive.len() {
        let mut file = archive.by_index(file_i)?;

        // skip any non .json files
        if file.name().ends_with(".json") {
            let file_size = file.size() as usize;

            if file_size > FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE {
                // buffer gets resized later automatically
                log::warn!(
                    "File \"{}\" with size {} is bigger than available buffer size ({})",
                    file.name(),
                    human_bytes::human_bytes(file.size() as f64),
                    human_bytes::human_bytes(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE as f64)
                );
            }

            let osv_record = {
                // faster than using serde_json::from_reader and BufReader
                file.read_to_string(&mut buffer)?;
                let res = serde_json::from_str::<OSVGeneralized>(&buffer);
                // todo: update to panic better
                // error probably because the schema updated
                let res_ok = match res {
                    Ok(v) => v,
                    Err(err) => {
                        log::error!("{}", &buffer);
                        panic!("{file_i}: {err}");
                    }
                };
                res_ok
            };
            let id = &osv_record.id;
            if id.len() > OSV_ID_MAX_CHARACTERS
                && id.chars().count() > OSV_ID_MAX_CHARACTERS {
                    panic!(
                        "ID {} has more characters ({}) than the maximum set to the database ({})",
                        id,
                        id.chars().count(),
                        OSV_ID_MAX_CHARACTERS
                    );
                }

            let generalized = GeneralizedCsvRecord::from_osv(osv_record);
            csv_writer.write_record(generalized.as_row())?;
            buffer.clear();
            bar.set_position((file_i + 1) as u64);
            processed_file_count += 1;
        }
    }

    csv_writer.flush()?;

    bar.finish();
    pg_bars.remove(&bar);
    log::info!(
        "Finished. Total processing time: {:?}",
        processing_start.elapsed()
    );

    Ok(processed_file_count)
}

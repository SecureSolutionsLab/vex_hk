use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};

use sqlx::{Execute, Executor, Postgres, QueryBuilder};
use zip::ZipArchive;

use crate::{
    db_api::consts::{GITHUB_REVIEWED_TABLE_NAME, GITHUB_UNREVIEWED_TABLE_NAME},
    download::download_and_save_to_file_in_chunks,
    scrape_mod::csv_postgres_integration::{self, CsvCreationError, GeneralizedCsvRecord},
};

use super::{
    OSVGitHubExtended, GITHUB_ID_CHARACTERS, REPOSITORY_URL, TEMP_CSV_FILE_PATH_REVIEWED,
    TEMP_CSV_FILE_PATH_UNREVIEWED, TEMP_DOWNLOAD_FILE_PATH,
};

const FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE: usize = 42_000_000; // 42mb

/// Download repository data from <REPOSITORY_URL> and send it to <GITHUB_REVIEWED_TABLE_NAME> for reviewed amd <GITHUB_UNREVIEWED_TABLE_NAME> tables for reviewed and unreviewed advisories, respectfully.
///
/// This operation is quite fast, and it does not involve the GitHub API, performing only one download. The only downside is that it is not incremental, requiring a full redownload each time the data needs to be updated.
/// 
/// It does not act on data that is already present in the database, instead recreating the tables each time, even when most information is already present
pub async fn download_osv_full(
    client: reqwest::Client,
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    log::info!("Starting a download a full copy of Github Advisory database.");

    let download_path = Path::new(TEMP_DOWNLOAD_FILE_PATH);
    let csv_path_reviewed = Path::new(TEMP_CSV_FILE_PATH_REVIEWED);
    let csv_path_unreviewed = Path::new(TEMP_CSV_FILE_PATH_UNREVIEWED);

    download_and_save_to_file_in_chunks(
        client,
        REPOSITORY_URL,
        Path::new(TEMP_DOWNLOAD_FILE_PATH),
        &pg_bars,
    )
    .await?;
    let (row_count_reviewed, row_count_unreviewed) = create_csv(
        download_path,
        csv_path_reviewed,
        csv_path_unreviewed,
        pg_bars,
    )
    .await?;

    log::info!("Recreating database table.");
    let database_delete_start = Instant::now();
    db_connection
        .execute(
            QueryBuilder::<Postgres>::new(format!(
                "
DROP TABLE IF EXISTS \"{GITHUB_REVIEWED_TABLE_NAME}\";
DROP TABLE IF EXISTS \"{GITHUB_UNREVIEWED_TABLE_NAME}\";
{}
{}
        ",
                super::get_create_table_text(GITHUB_REVIEWED_TABLE_NAME),
                super::get_create_table_text(GITHUB_UNREVIEWED_TABLE_NAME),
            ))
            .build()
            .sql(),
        )
        .await
        .unwrap();
    log::info!(
        "Creating new Github Advisories tables for GitHub-reviewed and unreviewed advisories, with names \"{}\" and \"{}\"",
        GITHUB_REVIEWED_TABLE_NAME,
        GITHUB_UNREVIEWED_TABLE_NAME
    );
    log::info!(
        "Finished recreating database table. Time: {:?}",
        database_delete_start.elapsed()
    );

    csv_postgres_integration::send_csv_to_database_whole(
        &db_connection,
        csv_path_reviewed,
        GITHUB_REVIEWED_TABLE_NAME,
        row_count_reviewed,
    )
    .await?;
    csv_postgres_integration::send_csv_to_database_whole(
        &db_connection,
        csv_path_unreviewed,
        GITHUB_UNREVIEWED_TABLE_NAME,
        row_count_unreviewed,
    )
    .await?;

    log::info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );

    fs::remove_file(TEMP_DOWNLOAD_FILE_PATH)?;
    fs::remove_file(TEMP_CSV_FILE_PATH_REVIEWED)?;
    fs::remove_file(TEMP_CSV_FILE_PATH_UNREVIEWED)?;
    Ok(())
}

/// Almost identical to OSV in functionality, however with added GitHub checks and reviewed/unreviewed subdivision. 
async fn create_csv(
    download: &Path,
    csv_reviewed: &Path,
    csv_unreviewed: &Path,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(usize, usize), CsvCreationError> {
    let processing_start = Instant::now();

    let download_file = File::open(download)?;
    let mut archive = ZipArchive::new(download_file)?;

    log::info!(
        "About to process and convert {} files to csv. Files created at {:?}, {:?}",
        archive.len(),
        csv_reviewed,
        csv_unreviewed
    );

    let bar = pg_bars.add(indicatif::ProgressBar::new(archive.len() as u64));

    {
        let parent = csv_reviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    {
        let parent = csv_unreviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    let mut csv_writer_reviewed = csv::WriterBuilder::new()
        .buffer_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE)
        .has_headers(false)
        .from_path(csv_reviewed)?;
    let mut csv_writer_unreviewed = csv::WriterBuilder::new()
        .buffer_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE)
        .has_headers(false)
        .from_path(csv_unreviewed)?;

    let mut buffer: String = String::with_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE);
    let mut processed_file_count_reviewed = 0;
    let mut processed_file_count_unreviewed = 0;
    for file_i in 0..archive.len() {
        let mut file = archive.by_index(file_i)?;
        let name = file.name();

        if name.ends_with(".json") {
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
        } else {
            continue;
        }

        let reviewed = if name.starts_with("advisory-database-main/advisories/github-reviewed") {
            true
        } else if name.starts_with("advisory-database-main/advisories/unreviewed") {
            false
        } else {
            continue;
        };

        let osv_record = {
            // faster than using serde_json::from_reader and BufReader
            file.read_to_string(&mut buffer)?;
            serde_json::from_str::<OSVGitHubExtended>(&buffer)
        };
        let osv_record = match osv_record {
            Ok(v) => v,
            Err(err) => {
                log::error!(
                    "Error reading file {:?}, {}\nSKIPPING",
                    file.enclosed_name(),
                    err
                );
                buffer.clear();
                continue;
            }
        };
        let id = &osv_record.id;
        if id.len() > GITHUB_ID_CHARACTERS {
            if id.chars().count() > GITHUB_ID_CHARACTERS {
                panic!(
                    "ID {} has more characters ({}) than the maximum set to the database ({})",
                    id,
                    id.chars().count(),
                    GITHUB_ID_CHARACTERS
                );
            }
        }

        let row_data = GeneralizedCsvRecord::from_osv(osv_record);
        let record: [&str; 4] = row_data.as_row();
        if reviewed {
            csv_writer_reviewed.write_record(&record)?;
            processed_file_count_reviewed += 1;
        } else {
            csv_writer_unreviewed.write_record(&record)?;
            processed_file_count_unreviewed += 1;
        }
        buffer.clear();

        bar.set_position((file_i + 1) as u64);
    }

    csv_writer_reviewed.flush()?;
    csv_writer_unreviewed.flush()?;

    bar.finish();
    pg_bars.remove(&bar);
    log::info!(
        "Finished. Total processing time: {:?}\nTotal number of processed files: {} (Reviewed), {} (Unreviewed)",
        processing_start.elapsed(),
        processed_file_count_reviewed,
        processed_file_count_unreviewed,
    );

    Ok((
        processed_file_count_reviewed,
        processed_file_count_unreviewed,
    ))
}

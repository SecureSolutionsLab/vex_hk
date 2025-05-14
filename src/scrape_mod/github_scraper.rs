use std::{fs::{self, File}, path::Path, time::Instant};

use sqlx::{Execute, Executor, Postgres, QueryBuilder};
use zip::ZipArchive;

use crate::{
    db_api::consts::{GITHUB_REVIEWED_TABLE_NAME, GITHUB_UNREVIEWED_TABLE_NAME},
    download::download_and_save_to_file_in_chunks,
};

const FULL_DATA_URL: &str =
    "https://github.com/github/advisory-database/archive/refs/heads/main.zip";

const FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE: usize = 42_000_000; // 42mb

const TIMESTAMP_FILE_NAME: &str = "last_timestamp_github";

const TEMP_FILE_PATH: &str = "./temp/github_all_temp.zip";

// https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
// ids come in the format of GHSA-xxxx-xxxx-xxxx
const GITHUB_ID_CHARACTERS: usize = 19;

pub async fn download_full(
    client: reqwest::Client,
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    log::info!("Creating new Github Advisories tables for GitHub-reviewed and unreviewed advisories, with names \"{}\" and \"{}\"",
GITHUB_REVIEWED_TABLE_NAME, GITHUB_UNREVIEWED_TABLE_NAME);

    db_connection
        .execute(
            QueryBuilder::<Postgres>::new(format!(
                "
        DROP TABLE IF EXISTS \"{GITHUB_REVIEWED_TABLE_NAME}\";
        DROP TABLE IF EXISTS \"{GITHUB_UNREVIEWED_TABLE_NAME}\";
        CREATE TABLE \"{GITHUB_REVIEWED_TABLE_NAME}\" (
            \"id\" character({GITHUB_ID_CHARACTERS}) PRIMARY KEY,
            \"data\" JSONB NOT NULL
        );
        CREATE TABLE \"{GITHUB_UNREVIEWED_TABLE_NAME}\" (
            \"id\" character({GITHUB_ID_CHARACTERS}) PRIMARY KEY,
            \"data\" JSONB NOT NULL
        );",
            ))
            .build()
            .sql(),
        )
        .await
        .unwrap();

    log::info!("Starting a download a full copy of Github Advisory database.");

    download_and_save_to_file_in_chunks(client, FULL_DATA_URL, Path::new(TEMP_FILE_PATH), &pg_bars)
        .await?;
    read_file_and_send_to_database(TEMP_FILE_PATH, db_connection, pg_bars).await?;
    // update_osv_timestamp()?;

    log::info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );

    //fs::remove_file(TEMP_FILE_PATH)?;
    Ok(())
}


pub async fn read_file_and_send_to_database<P>(
    file_path: P,
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: AsRef<std::path::Path>,
{
    let processing_start = Instant::now();

    let file = File::open(file_path)?;
    let mut archive = ZipArchive::new(file)?;

    log::info!("About to process {} files", archive.len());

    let bar = pg_bars.add(indicatif::ProgressBar::new(archive.len() as u64));

    for file_i in 0..archive.len() {
        let mut file = archive.by_index(file_i)?;

        println!("{:?}", file.enclosed_name().expect("Failed to extract name from file while extracting from zipfile"));

        // skip any non .json files
        if file.name().ends_with(".json") {

        }
    }

    bar.finish();
    pg_bars.remove(&bar);
    log::info!(
        "Finished. Total processing time: {:?}",
        processing_start.elapsed()
    );

    Ok(())
}
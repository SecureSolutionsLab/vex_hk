use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};

use chrono::Utc;
use sqlx::{Execute, Executor, Postgres, QueryBuilder};
use zip::ZipArchive;

use crate::{
    config::Config,
    csv_postgres_integration::{self, CsvCreationError, GeneralizedCsvRecord},
    download::download_and_save_to_file_in_chunks,
    scrape_mod::github::{
        GithubType, TEMP_CSV_FILE_REVIEWED_NAME, TEMP_CSV_FILE_UNREVIEWED_NAME,
        TEMP_DOWNLOAD_FILE_NAME,
    },
    state::ScraperState,
};

use super::{OSVGitHubExtended, GITHUB_ID_CHARACTERS};

const FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE: usize = 42_000_000; // 42mb

/// See [download_osv_full] for more information
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
    download_osv_full(config, client, db_connection, pg_bars, true).await?;
    state.save_download_github_osv_full(config, start_time);
    Ok(())
}

/// Perform download or update with regards to config and state
pub async fn sync(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    state: &mut ScraperState,
) -> anyhow::Result<()> {
    if !config.github.osv.enable_update {
        log::warn!("GitHub OSV sync called even though config is disabled. Continuing anyways.");
    }

    if !state.github.osv.initialized {
        log::info!("GitHub OSV is not initialized. Performing initial download.");
        return manual_download_and_save_state(config, client, db_connection, pg_bars, state).await;
    }

    todo!();
    // if config.github.osv.use_api_for_update {
    //     let Some(token) = config.tokens.github.as_ref() else {
    //         return Err(anyhow::anyhow!(
    //             "GitHub use_api_for_update enabled but API token not set. Bailing out."
    //         ));
    //     };
    //     let Some(last_timestamp_reviewed) =
    //         state.github.osv.last_update_timestamp_reviewed.as_ref()
    //     else {
    //         log::error!("GitHub OSV initialized, however last_timestamp_unreviewed is null. Data may be corrupted. Redownloading.");
    //         state.github.osv.initialized = false;
    //         return manual_download_and_save_state(config, client, db_connection, pg_bars, state)
    //             .await;
    //     };
    //     let Some(last_timestamp_unreviewed) =
    //         state.github.osv.last_update_timestamp_unreviewed.as_ref()
    //     else {
    //         log::error!("GitHub OSV initialized, however last_timestamp_reviewed is null. Data may be corrupted. Redownloading.");
    //         state.github.osv.initialized = false;
    //         return manual_download_and_save_state(config, client, db_connection, pg_bars, state)
    //             .await;
    //     };

    //     let start_time = Utc::now();
    //     let update_inst = Instant::now();

    //     let essentials_inst = update_inst.clone();
    //     log::info!(
    //         "Requesting a list of reviewed modified advisories after {}",
    //         last_timestamp_reviewed.format("%Y/%m/%d")
    //     );
    //     let essentials_reviewed = super::rest_api::get_only_essential_after_modified_date(
    //         config,
    //         client,
    //         token,
    //         last_timestamp_reviewed,
    //         GithubType::Reviewed,
    //     )
    //     .await?;
    //     log::info!(
    //         "Requesting a list of unreviewed modified advisories after {}",
    //         last_timestamp_reviewed.format("%Y/%m/%d")
    //     );
    //     let essentials_unreviewed = super::rest_api::get_only_essential_after_modified_date(
    //         config,
    //         client,
    //         token,
    //         last_timestamp_unreviewed,
    //         GithubType::Unreviewed,
    //     )
    //     .await?;
    //     log::info!(
    //         "Request finished. Total time: {:?}. Total number of advisories: {} reviewed, {} unreviewed)",
    //         essentials_inst.elapsed(),
    //         essentials_reviewed.len(),
    //         essentials_unreviewed.len()
    //     );

    //     if essentials_reviewed.len() + essentials_unreviewed.len()
    //         >= config.github.osv.full_download_threshold
    //     {
    //         log::warn!(
    //             "Threshold reached for API to OSV updates ({} >= {}). Performing full download.",
    //             essentials_reviewed.len() + essentials_unreviewed.len(),
    //             config.github.osv.full_download_threshold
    //         );
    //         return manual_download_and_save_state(config, client, db_connection, pg_bars, state)
    //             .await;
    //     }

    //     let GithubOsvUpdate::AllOk(updated_reviewed) =
    //         super::repository_update::update_osv_database_incremental(
    //             config,
    //             db_connection,
    //             pg_bars,
    //             client,
    //             token,
    //             GithubType::Reviewed,
    //             essentials_reviewed,
    //         )
    //         .await?
    //     else {
    //         log::warn!(
    //             "Reviewed update got rate limited. Postponing update. Time: {:?}",
    //             update_inst.elapsed()
    //         );
    //         return Ok(());
    //     };
    //     log::info!(
    //         "GitHub reviewed OSV table updated. {} rows modified. Time: {:?}",
    //         updated_reviewed,
    //         update_inst.elapsed()
    //     );
    //     state.save_update_github_osv_reviewed(config, start_time);

    //     let GithubOsvUpdate::AllOk(updated_unreviewed) =
    //         super::repository_update::update_osv_database_incremental(
    //             config,
    //             db_connection,
    //             pg_bars,
    //             client,
    //             token,
    //             GithubType::Unreviewed,
    //             essentials_unreviewed,
    //         )
    //         .await?
    //     else {
    //         log::warn!(
    //             "Unreviewed update got rate limited. Postponing update. Time: {:?}",
    //             update_inst.elapsed()
    //         );
    //         return Ok(());
    //     };
    //     log::info!(
    //         "GitHub unreviewed OSV table updated. {} rows modified. Time: {:?}",
    //         updated_unreviewed,
    //         update_inst.elapsed()
    //     );
    //     state.save_update_github_osv_unreviewed(config, start_time);

    //     log::info!("GitHub OSV table update finished successfully.");
    // } else {
    //     log::info!("GitHub OSV API update disabled. Performing full download.");
    //     return manual_download_and_save_state(config, client, db_connection, pg_bars, state).await;
    // }

    Ok(())
}

/// Download repository data from [REPOSITORY_URL] and send it to [crate::consts::GITHUB_OSV_REVIEWED_TABLE_NAME] for reviewed amd [crate::consts::GITHUB_OSV_UNREVIEWED_TABLE_NAME] tables for reviewed and unreviewed advisories, respectfully.
///
/// This operation is quite fast, and it does not involve the GitHub API, performing only one download. The only downside is that it is not incremental, requiring a full redownload each time the data needs to be updated.
///
/// Modes of operation:
///
///  - recreate_database_table set to true: Recreate both tables and completely repopulate them.
///  - recreate_database_table set to false: Try to update existing data by inserting or replacing old values with newer ones. This won't delete entries if they for some reason disappear from the repository. This won't create the tables if they don't exist. This won't check for any previously corrupted data.
pub async fn download_osv_full(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    recreate_database_table: bool,
) -> anyhow::Result<()> {
    let start = Instant::now();

    log::info!("Starting a download a full copy of Github Advisory database.");

    let download_path = config.temp_dir_path.join(TEMP_DOWNLOAD_FILE_NAME);
    let csv_path_reviewed = config.temp_dir_path.join(TEMP_CSV_FILE_REVIEWED_NAME);
    let csv_path_unreviewed = config.temp_dir_path.join(TEMP_CSV_FILE_UNREVIEWED_NAME);

    download_and_save_to_file_in_chunks(client, &config.github.osv.url, &download_path, &pg_bars)
        .await?;
    let (row_count_reviewed, row_count_unreviewed) = create_csv(
        &download_path,
        &csv_path_reviewed,
        &csv_path_unreviewed,
        pg_bars,
    )
    .await?;

    if recreate_database_table {
        log::info!("Recreating database table.");
        let database_delete_start = Instant::now();
        db_connection
            .execute(
                QueryBuilder::<Postgres>::new(format!(
                    "DROP TABLE IF EXISTS \"{}\";\nDROP TABLE IF EXISTS \"{}\";\n{}\n{}",
                    GithubType::Reviewed.osv_table_name(config),
                    GithubType::Unreviewed.osv_table_name(config),
                    GithubType::Reviewed.osv_format_sql_create_table_command(config),
                    GithubType::Unreviewed.osv_format_sql_create_table_command(config),
                ))
                .build()
                .sql(),
            )
            .await?;
        log::info!(
        "Creating new Github Advisories tables for GitHub-reviewed and unreviewed advisories, with names \"{}\" and \"{}\"",
        GithubType::Reviewed.osv_table_name(config),
        GithubType::Unreviewed.osv_table_name(config)
    );
        log::info!(
            "Finished recreating database table. Time: {:?}",
            database_delete_start.elapsed()
        );

        csv_postgres_integration::send_csv_to_database_whole(
            &db_connection,
            &csv_path_reviewed,
            GithubType::Reviewed.osv_table_name(config),
            row_count_reviewed,
        )
        .await?;
        csv_postgres_integration::send_csv_to_database_whole(
            &db_connection,
            &csv_path_unreviewed,
            GithubType::Unreviewed.osv_table_name(config),
            row_count_unreviewed,
        )
        .await?;
    } else {
        log::info!(
            "Attempting an update on existing tables. Number of entries: {}, {}",
            row_count_reviewed,
            row_count_unreviewed
        );

        csv_postgres_integration::insert_and_replace_older_entries_in_database_from_csv(
            &db_connection,
            &csv_path_reviewed,
            GithubType::Reviewed.osv_table_name(config),
        )
        .await?;
        csv_postgres_integration::insert_and_replace_older_entries_in_database_from_csv(
            &db_connection,
            &csv_path_unreviewed,
            GithubType::Unreviewed.osv_table_name(config),
        )
        .await?;
    }

    log::info!("Removing temporary files");
    fs::remove_file(download_path)?;
    fs::remove_file(csv_path_reviewed)?;
    fs::remove_file(csv_path_unreviewed)?;

    log::info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );
    Ok(())
}

/// Almost identical to OSV in functionality, however with added GitHub checks and reviewed/unreviewed subdivision.
///
/// Returns row count for (reviewed, unreviewed).
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
        super::assert_osv_github_id(id);

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

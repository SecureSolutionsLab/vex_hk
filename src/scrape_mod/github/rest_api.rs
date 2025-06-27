use std::{fs, path::Path, time::Instant};

use chrono::{DateTime, Utc};
use sqlx::{Execute, Executor, Postgres, QueryBuilder};

use crate::{
    config::Config,
    csv_postgres_integration::{self, GeneralizedCsvRecord},
    db_api,
    scrape_mod::github::api_response::GitHubAdvisoryAPIResponse,
    state::ScraperState,
};

use super::{paginated_api::PaginatedApiDataIter, GithubApiDownloadError, GithubType};

/// Perform download or update with regards to config and state
pub async fn sync(
    config: &Config,
    state: &mut ScraperState,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    client: &reqwest::Client,
    ty: GithubType,
) -> anyhow::Result<()> {
    let enable_update = match ty {
        GithubType::Reviewed => config.github.api.enable_update_reviewed,
        GithubType::Unreviewed => config.github.api.enable_update_unreviewed,
    };
    if !enable_update {
        log::warn!("GitHub API sync called even though config is disabled. Continuing anyways.");
    }

    let Some(token) = config.tokens.github.as_ref() else {
        return Err(anyhow::anyhow!(
            "GitHub API token not set. GiHub API sync is not possible."
        ));
    };

    if !state.get_github_api_state(ty).initialized {
        log::info!(
            "GitHub API ({ty}) is not initialized. Performing / continuing initial download."
        );
        return download_all_entries(config, state, db_pool, client, &token, ty).await;
    }

    let Some(last_timestamp) = state
        .get_github_api_state(ty)
        .last_update_timestamp
        .as_ref()
    else {
        log::error!("GitHub API ({ty}) initialized, however last_timestamp is null. Data may be corrupted. Redownloading.");
        state.get_github_api_state(ty).initialized = false;
        return download_all_entries(config, state, db_pool, client, &token, ty).await;
    };

    log::info!("Beginning GitHub API update. Note that the API doesn't distinguish time intervals in less than a day, so multiple updates in a day can lead to the same results.");

    let start_time = Utc::now();
    let start_inst = Instant::now();
    let csv_path = config.temp_dir_path.join(ty.csv_general_tmp_file_path());
    {
        let parent = csv_path.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    let size = api_data_after_update_date_single_csv_file(
        config,
        client,
        &token,
        &csv_path,
        *last_timestamp,
        ty,
    )
    .await?;
    if size > 0 {
        let mut conn = db_pool.acquire().await?;
        csv_postgres_integration::insert_and_replace_any_in_database_from_csv(
            &mut conn,
            &csv_path,
            ty.api_table_name(config),
            ty.tmp_table_name(),
        )
        .await?;
    }
    state.save_update_github_api(config, start_time, ty);
    log::info!(
        "Finished updating API. Entry count: {size}. Time: {:?}",
        start_inst.elapsed()
    );

    Ok(())
}

/// Download all entries from the API for a specific type.
///
/// This function saves state between invocations, so it can continue in case of error (like for example by becoming rate limited)
pub async fn download_all_entries(
    config: &Config,
    state: &mut ScraperState,
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    client: &reqwest::Client,
    token: &str,
    ty: GithubType,
) -> anyhow::Result<()> {
    {
        let mut conn = db_pool.acquire().await?;
        let ty_state = state.get_github_api_state(ty);

        let next_url_opt = ty_state.current_initialization_next_link.clone();
        let mut paginated_iter = if ty_state.in_initialization {
            let next_url = next_url_opt
                .as_ref()
                .expect("GitHub API state is in initialization, however next_link value is None");
            PaginatedApiDataIter::new(client, next_url, token, &[("type", ty.api_str())])?
        } else {
            log::info!("Creating API initialization table.");
            conn.execute(
                QueryBuilder::<Postgres>::new(format!(
                    "DROP TABLE IF EXISTS \"{}\";\n{}",
                    ty.api_initialization_table_name(config),
                    ty.api_initialization_format_sql_create_table_command(config),
                ))
                .build()
                .sql(),
            )
            .await?;

            let start_time = Utc::now();
            let start_link = &config.github.api.url;
            state.save_download_github_api_initialization_start(
                config,
                start_time,
                start_link.clone(),
                ty,
            );

            PaginatedApiDataIter::new(client, &start_link, token, &[("type", ty.api_str())])?
        };
        let csv_path = config.temp_dir_path.join(ty.csv_general_tmp_file_path());

        {
            let parent = csv_path.parent().unwrap();
            if !fs::exists(parent)? {
                fs::create_dir_all(parent)?;
            }
        }

        while let Some(response_res) = paginated_iter.next_page_request().await {
            let response = response_res.map_err(|err| anyhow::anyhow!("Next request failed, but data was saved. This function can continue another time. Error:\n{}", err))?;
            log::info!(
                "Received next page response from url {}. Rate remaining: {:?}.",
                response.url(),
                response.headers().get("x-ratelimit-remaining")
            );

            let next_page_data: Vec<GitHubAdvisoryAPIResponse> =
                response.json().await.map_err(|err| {
                    anyhow::anyhow!("Failed to process next request data. Error:\n{}", err)
                })?;
            let page_size = next_page_data.len();

            {
                let mut writer = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_path(&csv_path)?;
                for advisory in next_page_data {
                    let record = GeneralizedCsvRecord::from_github_api_response(advisory);
                    writer.write_record(record.as_row()).map_err(|err| {
                        anyhow::anyhow!(
                        "Failed to write data to CSV before sending it to the database. Error:\n{}",
                        err
                    )
                    })?;
                }
            }

            log::info!("Sending data ({} rows) to initialization table.", page_size);
            csv_postgres_integration::execute_send_csv_to_database_whole(
                &mut conn,
                &csv_path,
                ty.api_initialization_table_name(config),
                page_size,
            )
            .await
            .map_err(|err| {
                anyhow::anyhow!("Failed to send data to the database. Error:\n{}", err)
            })?;

            state.save_download_github_api_initialization_in_progress(
                config,
                paginated_iter.get_next_url().to_string(),
                ty,
            );
        }
    }

    log::info!("All requests completed! Sending all data to main API table.");

    {
        log::info!("Starting final transaction.");
        let mut tx_conn = db_pool.begin().await?;

        log::info!("Creating API table.");
        tx_conn
            .execute(
                QueryBuilder::<Postgres>::new(format!(
                    "DROP TABLE IF EXISTS \"{}\";\n{}",
                    ty.api_table_name(config),
                    ty.api_format_sql_create_table_command(config),
                ))
                .build()
                .sql(),
            )
            .await?;

        log::info!("Inserting values from the initialization to the final table");
        db_api::insert::execute_insert_from_one_table_to_another(
            &mut tx_conn,
            ty.api_initialization_table_name(config),
            ty.api_table_name(config),
        )
        .await?;

        log::info!(
            "Deleting initialization table ({})",
            ty.api_initialization_table_name(config)
        );
        tx_conn
            .execute(
                QueryBuilder::<Postgres>::new(format!(
                    "DROP TABLE \"{}\";",
                    ty.api_initialization_table_name(config),
                ))
                .build()
                .sql(),
            )
            .await?;

        log::info!("Committing final transaction");
        tx_conn.commit().await?;

        state.save_download_github_api_initialization_finished(config, ty);
    }

    Ok(())
}

/// Download and save data in one single csv file, in [crate::csv_postgres_integration::GeneralizedCsvRecord] format
///
/// Download advisories modified after a specific date (inclusive, includes the day itself). Saves everything in a CSV file, where each row corresponds to one advisory. See [crate::csv_postgres_integration] for details.
///
/// Note: this function does NOT save progress during requests, and it won't be able to continue if it gets interrupted or an error occurs, so it should NOT be used for long or error-prone downloads that may require more than the API limit of requests for one hour.
///
/// Returns the number of total entries.
pub async fn api_data_after_update_date_single_csv_file(
    config: &Config,
    client: &reqwest::Client,
    token: &str,
    csv_file_path: &Path,
    date: DateTime<Utc>,
    ty: GithubType,
) -> Result<usize, GithubApiDownloadError> {
    {
        let parent = csv_file_path.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(csv_file_path)?;

    log::info!(
        "Performing requests to the GitHub API and saving data to CSV. CSV File created at {csv_file_path:?}"
    );

    let mut paginated_iter = PaginatedApiDataIter::new(
        client,
        &config.github.api.url,
        token,
        &[
            ("modified", &date.format(">=%Y-%m-%d").to_string()),
            ("type", ty.api_str()),
        ],
    )?;
    let mut total_entries = 0;
    while let Some(next_page_res) = paginated_iter.next_page_data().await {
        let next_page_data: Vec<GitHubAdvisoryAPIResponse> = next_page_res?;
        total_entries += next_page_data.len();

        for advisory in next_page_data {
            let record = GeneralizedCsvRecord::from_github_api_response(advisory);
            writer.write_record(record.as_row())?;
        }
    }
    writer.flush()?;

    Ok(total_entries)
}

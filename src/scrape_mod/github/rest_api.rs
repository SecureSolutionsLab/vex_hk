use std::{fs, path::Path};

use serde::Deserialize;

use crate::{config::Config, csv_postgres_integration::GeneralizedCsvRecord};

use super::{
    paginated_api::PaginatedApiDataIter,
    GithubApiDownloadError, GithubType,
};

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
    date: chrono::NaiveDate,
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
            ("published", &date.format(">=%Y-%m-%d").to_string()),
            ("type", ty.api_str()),
        ],
    )?;
    let mut total_entries = 0;
    while let Some(next_page_res) = paginated_iter.next_page_data().await {
        let next_page_data = next_page_res?;
        total_entries += next_page_data.len();

        for advisory in next_page_data {
            let record = GeneralizedCsvRecord::from_github_api_response(advisory);
            writer.write_record(record.as_row())?;
        }
    }
    writer.flush()?;

    Ok(total_entries)
}

use std::io::Read;

use crate::{db_api, scrape_mod::github, GITHUB_TOKEN_LOCATION};

// todo
pub async fn update_github(
    pg_bars: &indicatif::MultiProgress,
) -> Result<github::GithubOsvUpdate, github::GithubApiDownloadError> {
    let token = {
        let mut buf = String::new();
        let mut file = std::fs::File::open(GITHUB_TOKEN_LOCATION).unwrap();
        file.read_to_string(&mut buf).unwrap();
        buf
    };
    let client = reqwest::Client::new();
    let db_conn = db_api::db_connection::get_db_connection().await.unwrap();

    github::read_ids_and_download_files_into_database(
        db_conn,
        pg_bars,
        &client,
        &token,
        chrono::NaiveDate::from_ymd_opt(2025, 5, 1).unwrap(), // todo
        github::GithubApiDownloadType::Reviewed,
    )
    .await
}

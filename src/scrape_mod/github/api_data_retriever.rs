use std::{fs, io::{BufWriter, Write}, path::Path};

use regex::Regex;
use serde::Serialize;

use crate::download::DownloadError;

use super::api_response::GitHubAdvisoryAPIResponse;

// https://stackoverflow.com/questions/3809401/what-is-a-good-regular-expression-to-match-a-url
const URL_MATCH: &str = r"https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.~#?&//=]*)";

pub struct PaginatedGithubAdvisoriesDataIter<'a> {
    client: &'a reqwest::Client,
    header_next_pattern: Regex,
    request: reqwest::Request,
    finished: bool,
}

impl<'a> PaginatedGithubAdvisoriesDataIter<'a> {
    pub fn new(
        client: &'a reqwest::Client,
        token: &'a str,
        query: &[(&str, &str)],
    ) -> Result<Self, reqwest::Error> {
        let next_pattern = Regex::new(&("<(".to_owned() + URL_MATCH + ")>; rel=\"next\"")).unwrap();

        let request = client
            .get("https://api.github.com/advisories")
            .bearer_auth(token)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "User")
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .query(&[("per_page", "100")])
            .query(query)
            .build()?;

        Ok(Self {
            client,
            header_next_pattern: next_pattern,
            request,
            finished: false,
        })
    }

    pub async fn next_page_data(
        &mut self,
    ) -> Option<Result<Vec<GitHubAdvisoryAPIResponse>, reqwest::Error>> {
        if self.finished {
            return None;
        }
        Some(self.next_page_data_perform_request().await)
    }

    async fn next_page_data_perform_request(
        &mut self,
    ) -> Result<Vec<GitHubAdvisoryAPIResponse>, reqwest::Error> {
        println!("{:#?}", self.request.try_clone().unwrap());

        let response = self
            .client
            .execute(self.request.try_clone().unwrap())
            .await?;

        println!("{:#?}", response);

        let next_url_opt = if let Some(link_header) = response.headers().get("link") {
            self.header_next_pattern
                .captures(
                    link_header
                        .to_str()
                        .expect("Failed to convert HTTP header to valid string"),
                )
                .map(|captures| captures.get(1).unwrap().as_str().to_owned())
        } else {
            None
        };

        let data = response
            .json::<crate::scrape_mod::github::api_response::GitHubAdvisoryAPIResponses>()
            .await
            .unwrap();

        if let Some(next_url) = next_url_opt {
            let url = self.request.url_mut();
            *url = reqwest::Url::parse(&next_url)
                .expect("Failed to parse url returned from pagination header");
        } else {
            self.finished = true;
        }

        Ok(data)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GithubApiDownloadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Reqwest HTTP Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to serialize data to json")]
    Serialization(#[from] serde_json::Error),
}

// "malware" unimplemented
#[derive(Clone, Copy)]
pub enum GithubApiDownloadType {
    Reviewed,
    Unreviewed,
}

impl GithubApiDownloadType {
    pub fn api_str(self) -> &'static str {
        match self {
            Self::Reviewed => "reviewed",
            Self::Unreviewed => "unreviewed",
        }
    }

    pub fn path_str(self) -> &'static str {
        match self {
            Self::Reviewed => "github-reviewed",
            Self::Unreviewed => "unreviewed",
        }
    }
}


// save full files in directory
pub async fn download_and_save_api_data_after_update_date(
    client: &reqwest::Client,
    token: &str,
    save_dir_path: &Path,
    date: chrono::NaiveDate,
    ty: GithubApiDownloadType,
) -> Result<(usize, usize), GithubApiDownloadError> {
    {
        if !fs::exists(save_dir_path)? {
            fs::create_dir_all(save_dir_path)?;
        } else {
            fs::remove_dir_all(save_dir_path)?;
            fs::create_dir(save_dir_path)?;
        }
    }

    let mut paginated_iter = PaginatedGithubAdvisoriesDataIter::new(
        client,
        token,
        &[
            ("published", &date.format(">=%Y-%m-%d").to_string()),
            ("type", ty.api_str()),
        ],
    )?;
    let mut total_entries = 0;
    let mut i = 0;
    let mut buffer = Vec::new();
    while let Some(next_page_res) = paginated_iter.next_page_data().await {
        let next_page_data = next_page_res?;
        total_entries += next_page_data.len();

        let mut file =
            std::fs::File::create(format!("{}/{}.json", save_dir_path.to_str().unwrap(), i))?;
        serde_json::to_writer_pretty(&mut buffer, &next_page_data)?;
        file.write_all(&mut buffer)?;
        file.flush()?;
        buffer.clear();

        i += 1;
    }

    Ok((total_entries, i))
}

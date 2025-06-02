use regex::Regex;

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
            .query(&[("per_page", "10")])
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

    pub async fn next_page_data_perform_request(
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

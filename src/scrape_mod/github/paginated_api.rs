use regex::Regex;

// https://stackoverflow.com/questions/3809401/what-is-a-good-regular-expression-to-match-a-url
const URL_MATCH: &str = r"https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.~#?&//=]*)";

/// # Retrieve paginated data from the rest api
///
/// Functions like an iterator, however that trait can't be implemented asyncfully in a safe fashion
/// (as of time of writing)
pub struct PaginatedApiDataIter<'a> {
    client: &'a reqwest::Client,
    header_next_pattern: Regex,
    request: reqwest::Request,
    finished: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PaginatedApiDataIterError {
    #[error("Failed to make request: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to deserialize: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl<'a> PaginatedApiDataIter<'a> {
    /// Parse and store the information relative to the request.
    ///
    /// The first request won't happen until [PaginatedApiDataIter::next_page_data] is called for the first time.
    ///
    /// See <https://docs.github.com/en/rest/security-advisories/global-advisories> for information on query parameters. This only refers to the query arguments linked to the http query itself, not the headers.
    pub fn new(
        client: &'a reqwest::Client,
        api_url: &'a str,
        token: &'a str,
        query: &[(&str, &str)],
    ) -> Result<Self, reqwest::Error> {
        let next_pattern = Regex::new(&("<(".to_owned() + URL_MATCH + ")>; rel=\"next\"")).unwrap();

        let request = client
            .get(api_url)
            .bearer_auth(token)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "User")
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .query(&[("per_page", "100")])
            .query(query)
            .build()?;
        log::debug!(
            "Created PaginatedApiDataIter. Main request:\n{:#?}",
            request
        );

        Ok(Self {
            client,
            header_next_pattern: next_pattern,
            request,
            finished: false,
        })
    }

    /// Perform a request for the next page, and just return the json object
    ///
    /// As [PaginatedApiDataIter] functions as a iterator, this function will continuously return None if no new information is left to fetch.
    pub async fn next_page_request(
        &mut self,
    ) -> Option<Result<reqwest::Response, PaginatedApiDataIterError>> {
        if self.finished {
            return None;
        }
        Some(self.next_page_data_perform_only_request().await)
    }

    /// Perform a request for the next page, and parse json array to a vec
    ///
    /// As [PaginatedApiDataIter] functions as a iterator, this function will continuously return None if no new information is left to fetch.
    pub async fn next_page_data<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Option<Result<Vec<T>, PaginatedApiDataIterError>> {
        if self.finished {
            return None;
        }
        Some(self.next_page_data_perform_request_and_parse_data().await)
    }

    async fn next_page_data_perform_only_request(
        &mut self,
    ) -> Result<reqwest::Response, PaginatedApiDataIterError> {
        let response = self
            .client
            .execute(self.request.try_clone().unwrap())
            .await?;
        log::debug!("Received response:\n{:#?}", response);

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

        if let Some(next_url) = next_url_opt {
            let url = self.request.url_mut();
            *url = reqwest::Url::parse(&next_url)
                .expect("Failed to parse url returned from pagination header");
        } else {
            self.finished = true;
        }

        Ok(response)
    }

    async fn next_page_data_perform_request_and_parse_data<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<Vec<T>, PaginatedApiDataIterError> {
        let response = self.next_page_data_perform_only_request().await?;

        log::debug!("Decoding data");
        let data = response.json::<Vec<T>>().await?;
        Ok(data)
    }

    /// Exhaust paging iterator and get all data at once in a single vec
    ///
    /// If an error occurs mid requests some data will be lost, so self is consumed
    pub async fn exhaust<T: serde::de::DeserializeOwned>(
        mut self,
    ) -> Result<Vec<T>, PaginatedApiDataIterError> {
        let mut data = Vec::new();
        while let Some(next_page_res) = self.next_page_data().await {
            data.extend(next_page_res?);
        }
        Ok(data)
    }
}

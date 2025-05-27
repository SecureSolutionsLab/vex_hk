use regex::Regex;

use super::api_response::GitHubAdvisoryAPIResponse;

// https://stackoverflow.com/questions/3809401/what-is-a-good-regular-expression-to-match-a-url
const URL_MATCH: &str = r"https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.~#?&//=]*)";

pub async fn get_paginated_github_advisories_data(
    client: reqwest::Client,
    token: String,
    query: &[(&str, &str)],
) -> Vec<GitHubAdvisoryAPIResponse> {
    let next_pattern = Regex::new(&("<(".to_owned() + URL_MATCH + ")>; rel=\"next\"")).unwrap();

    let mut request = client
        .get("https://api.github.com/advisories")
        .bearer_auth(token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, "User")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .query(query)
        .build()
        .unwrap();

    loop {
        println!("{:#?}", request.try_clone().unwrap());

        let response = client.execute(request.try_clone().unwrap()).await.unwrap();

        println!("{:#?}", response);

        let next_url_opt = if let Some(link_header) = response.headers().get("link") {
            next_pattern
                .captures(
                    link_header
                        .to_str()
                        .expect("Failed to convert HTTP header to valid string"),
                )
                .map(|captures| captures.get(1).unwrap().as_str().to_owned())
        } else {
            None
        };

        {
            // // save response text for debugging
            // let text = response .text().await.unwrap();
            // let mut file = std::fs::File::create("./temp/out").unwrap();
            // file.write_all(&text.as_bytes()).unwrap();
            // file.flush().unwrap();

            let data = response
                .json::<crate::scrape_mod::github::api_response::GitHubAdvisoryAPIResponses>()
                .await
                .unwrap();
            // println!("{:#?}", data);

            println!("{}", data.len());
        }

        let Some(next_url) = next_url_opt else {
            break;
        };

        println!("next {:?}", next_url);

        {
            let url = request.url_mut();
            *url = reqwest::Url::parse(&next_url)
                .expect("Failed to parse url returned from pagination header");
        }
    }

    Vec::new()
}

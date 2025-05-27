use chrono::{DateTime, Utc};

pub type GitHubAdvisoryAPIResponses = Vec<GitHubAdvisoryAPIResponse>;

// https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponse {
    ghsa_id: String,
    cve_id: String,
    url: String,
    html_url: String,
    repository_advisory_url: Option<String>,
    summary: String,
    description: Option<String>,
    r#type: GitHubAdvisoryAPIResponseType,
    severity: GitHubAdvisoryAPIResponseSeverity,
    source_code_location: Option<String>,
    identifiers: Option<Vec<GitHubAdvisoryAPIResponseSeverityIdentifier>>,
    references: Option<Vec<String>>,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    github_reviewed_at: Option<DateTime<Utc>>,
    nvd_published_at: Option<DateTime<Utc>>,
    withdrawn_at: Option<DateTime<Utc>>,
    vulnerabilities: Option<Vec<GitHubAdvisoryAPIResponseSeverityVulnerability>>,
    cvss: Option<GitHubAdvisoryAPIResponseCVSS>,
    #[serde(default)]
    cvss_severities: Option<GitHubAdvisoryAPIResponseCVSSSeverities>,
    #[serde(default)]
    epss: Option<GitHubAdvisoryAPIResponseEPSS>,
    cwes: Option<Vec<GitHubAdvisoryAPIResponseCWE>>,
    credits: Option<Vec<GitHubAdvisoryAPIResponseCreditsItem>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAdvisoryAPIResponseType {
    Reviewed,
    Unreviewed,
    Malware,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAdvisoryAPIResponseSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseSeverityIdentifier {
    r#type: GitHubAdvisoryAPIResponseSeverityIdentifierType,
    value: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GitHubAdvisoryAPIResponseSeverityIdentifierType {
    CVE,
    GHSA,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseSeverityVulnerability {
    package: Option<GitHubAdvisoryAPIResponseSeverityVulnerabilityPackage>,
    vulnerable_version_range: Option<String>,
    first_patched_version: Option<String>,
    vulnerable_functions: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseSeverityVulnerabilityPackage {
    ecosystem: GitHubAdvisoryAPIResponseSeverityVulnerabilityEcosystem,
    name: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAdvisoryAPIResponseSeverityVulnerabilityEcosystem {
    Rubygems,
    Npm,
    Pip,
    Maven,
    Nuget,
    Composer,
    Go,
    Rust,
    Erlang,
    Actions,
    Pub,
    Other,
    Swift,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCVSS {
    vector_string: Option<String>,
    score: Option<f32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCVSSSeverities {
    cvss_v3: Option<GitHubAdvisoryAPIResponseCVSS>,
    cvss_v4: Option<GitHubAdvisoryAPIResponseCVSS>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseEPSS {
    #[serde(default)]
    percentage: Option<f32>,
    #[serde(default)]
    percentile: Option<f32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCWE {
    cwe_id: String,
    name: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCreditsItem {
    user: GitHubAdvisoryAPIResponseCreditsUser,
    r#type: GitHubAdvisoryAPIResponseCreditsItemType,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCreditsUser {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    login: String,
    id: u64,
    node_id: String,
    avatar_url: String,
    gravatar_id: Option<String>,
    url: String,
    html_url: String,
    followers_url: String,
    following_url: String,
    gists_url: String,
    starred_url: String,
    subscriptions_url: String,
    organizations_url: String,
    repos_url: String,
    events_url: String,
    received_events_url: String,
    r#type: String,
    site_admin: bool,
    #[serde(default)]
    starred_at: Option<String>,
    #[serde(default)]
    user_view_type: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubAdvisoryAPIResponseCreditsItemType {
    Analyst,
    Finder,
    Reporter,
    Coordinator,
    RemediationDeveloper,
    RemediationReviewer,
    RemediationVerifier,
    Tool,
    Sponsor,
    Other,
}

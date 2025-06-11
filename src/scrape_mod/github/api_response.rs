use chrono::{DateTime, Utc};

use super::OSVGitHubExtended;

pub type GitHubAdvisoryAPIResponses = Vec<GitHubAdvisoryAPIResponse>;

// https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
// most fields are required, only cvss_severities and epss are not
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponse {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub url: String,
    pub html_url: String,
    pub repository_advisory_url: Option<String>,
    pub summary: String,
    pub description: Option<String>,
    pub r#type: GitHubAdvisoryAPIResponseType,
    pub severity: GitHubAdvisoryAPIResponseSeverity,
    pub source_code_location: Option<String>,
    pub identifiers: Option<Vec<GitHubAdvisoryAPIResponseSeverityIdentifier>>,
    pub references: Option<Vec<String>>,
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub github_reviewed_at: Option<DateTime<Utc>>,
    pub nvd_published_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub vulnerabilities: Option<Vec<GitHubAdvisoryAPIResponseSeverityVulnerability>>,
    pub cvss: Option<GitHubAdvisoryAPIResponseCVSS>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cvss_severities: Option<GitHubAdvisoryAPIResponseCVSSSeverities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub epss: Option<GitHubAdvisoryAPIResponseEPSS>,
    pub cwes: Option<Vec<GitHubAdvisoryAPIResponseCWE>>,
    pub credits: Option<Vec<GitHubAdvisoryAPIResponseCreditsItem>>,
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
    pub r#type: GitHubAdvisoryAPIResponseSeverityIdentifierType,
    pub value: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GitHubAdvisoryAPIResponseSeverityIdentifierType {
    Cve,
    Ghsa,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseSeverityVulnerability {
    pub package: Option<GitHubAdvisoryAPIResponseSeverityVulnerabilityPackage>,
    pub vulnerable_version_range: Option<String>,
    pub first_patched_version: Option<String>,
    pub vulnerable_functions: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseSeverityVulnerabilityPackage {
    pub ecosystem: GitHubAdvisoryAPIResponseSeverityVulnerabilityEcosystem,
    pub name: Option<String>,
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
    pub vector_string: Option<String>,
    pub score: Option<f32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCVSSSeverities {
    pub cvss_v3: Option<GitHubAdvisoryAPIResponseCVSS>,
    pub cvss_v4: Option<GitHubAdvisoryAPIResponseCVSS>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseEPSS {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub percentage: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub percentile: Option<f32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCWE {
    pub cwe_id: String,
    pub name: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCreditsItem {
    pub user: GitHubAdvisoryAPIResponseCreditsUser,
    pub r#type: GitHubAdvisoryAPIResponseCreditsItemType,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAdvisoryAPIResponseCreditsUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub email: Option<String>,
    pub login: String,
    pub id: u64,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: Option<String>,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    pub r#type: String,
    pub site_admin: bool,
    #[serde(default)]
    pub starred_at: Option<String>,
    #[serde(default)]
    pub user_view_type: Option<String>,
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

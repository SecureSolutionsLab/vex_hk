use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// https://github.com/ossf/osv-schema/blob/main/validation/schema.json
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OSV<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub schema_version: Option<String>,
    pub id: String,              // required
    pub modified: DateTime<Utc>, // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub published: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub withdrawn: Option<DateTime<Utc>>,
    #[serde(default)]
    pub aliases: Option<Vec<String>>, // can be null
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub related: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub upstream: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Option<Vec<Severity>>, // can be null
    #[serde(default)]
    pub affected: Option<Vec<Affected>>, // can be null
    #[serde(default)]
    pub references: Option<Vec<Reference>>, // can be null
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub credits: Option<Vec<Credit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub database_specific: Option<T>,
}

pub type OSVGeneralized = OSV<serde_json::Value>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Severity {
    pub r#type: SeverityType, // required
    pub score: String,        // required
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SeverityType {
    #[serde(rename = "CVSS_V2")]
    CvssV2,
    #[serde(rename = "CVSS_V3")]
    CvssV3,
    #[serde(rename = "CVSS_V4")]
    CvssV4,
    Ubuntu,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Affected {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub package: Option<Package>,
    #[serde(default)]
    pub severity: Option<Vec<Severity>>, // can be null
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ranges: Option<Vec<Range>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub versions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: String, // required
    pub name: String,      // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Range {
    pub r#type: RangeType, // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub repo: Option<String>,
    pub events: Vec<Event>, // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RangeType {
    GIT,
    SEMVER,
    ECOSYSTEM,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    Introduced { introduced: String },
    Fixed { fixed: String },
    LastAffected { last_affected: String },
    Limit { limit: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    pub r#type: ReferenceType, // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    // Warn
    pub url: Option<String>, // required, but sometimes it is missing
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReferenceType {
    Advisory,
    Article,
    Detection,
    Discussion,
    Report,
    Fix,
    Introduced,
    Git,
    Package,
    Evidence,
    Web,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credit {
    pub name: String, // required
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub r#type: Option<CreditType>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreditType {
    Finder,
    Reporter,
    Analyst,
    Coordinator,
    RemediationDeveloper,
    RemediationReviewer,
    RemediationVerifier,
    Tool,
    Sponsor,
    Other,
}

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use chrono::{DateTime, FixedOffset};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct NVDCve {
    pub id: String,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: String,

    pub descriptions: Vec<Description>,
    pub metrics: Metrics,
    #[serde(default)]
    pub weaknesses: Vec<Weaknesses>,
    #[serde(default)]
    pub configurations: Vec<Configurations>,

    pub references: Vec<References>,
}


#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Description {
    pub lang: String,
    pub value: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Metrics {
    #[serde(rename = "cvssMetricV2", default)]
    pub cvss_metrics_v2: Vec<CVSSMetricsV2>,
    #[serde(rename = "cvssMetricV30", default)]
    pub cvss_metrics_v3: Vec<CVSSMetricsV3>,
    #[serde(rename = "cvssMetricV31", default)]
    pub cvss_metrics_v31: Vec<CVSSMetricsV3>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CVSSMetricsV2 {
    pub source: String,
    #[serde(rename = "type")]
    v2metric_type: String,
    #[serde(rename = "cvssData")]
    pub cvss_data: CVSSData,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f64,
    #[serde(rename = "impactScore")]
    pub impact_score: f64,
    #[serde(rename = "acInsufInfo")]
    pub ac_insuf_info: bool,
    #[serde(rename = "obtainAllPrivilege")]
    pub obtain_all_privilege: bool,
    #[serde(rename = "obtainUserPrivilege")]
    pub obtain_user_privilege: bool,
    #[serde(rename = "obtainOtherPrivilege")]
    pub obtain_other_privilege: bool,
    #[serde(rename = "userInteractionRequired", default)]
    pub user_interaction_required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CVSSData {
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: String,

    //V2
    #[serde(rename = "accessVector", default)]
    access_vector: String,
    #[serde(rename = "accessComplexity", default)]
    access_complexity: String,
    #[serde(default)]
    authentication: String,
    #[serde(rename = "confidentialityImpact", default)]
    confidentiality_impact: String,
    #[serde(rename = "integrityImpact", default)]
    integrity_impact: String,
    #[serde(rename = "availabilityImpact", default)]
    availability_impact: String,
    #[serde(rename = "baseScore", default)]
    pub base_score: f64,

    //V3
    #[serde(rename = "attackVector", default)]
    pub attack_vector: String,
    #[serde(rename = "attackComplexity", default)]
    attack_complexity: String,
    #[serde(rename = "privilegesRequired", default)]
    privileges_required: String,
    #[serde(rename = "userInteraction", default)]
    user_interaction: String,
    #[serde(default)]
    scope: String,
    #[serde(rename = "baseSeverity", default)]
    pub base_severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CVSSMetricsV3 {
    pub source: String,
    #[serde(rename = "type")]
    pub v3metric_type: String,
    #[serde(rename = "cvssData")]
    pub cvss_data: CVSSData,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f64,
    #[serde(rename = "impactScore")]
    pub impact_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Weaknesses {
    pub source: String,
    #[serde(rename = "type")]
    pub weakness_type: String,
    pub description: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Configurations {
    #[serde(default)]
    pub operator: String,
    pub nodes: Vec<Nodes>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Nodes {
    pub operator: String,
    pub negate: bool,
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Vec<CPEMatch>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CPEMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(rename = "versionStartExcluding", default)]
    pub version_begin_excl: String,
    #[serde(rename = "versionStartIncluding", default)]
    pub version_begin_incl: String,
    #[serde(rename = "versionEndIncluding", default)]
    pub version_end_incl: String,
    #[serde(rename = "versionEndExcluding", default)]
    pub version_end_excl: String,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct References {
    url: String,
    source: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct NvdResponse {
    #[serde(rename = "totalResults")]
    pub total_results: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilteredCVE {
    pub id: String,
    pub source_identifier: String,
    pub published: String,
    pub last_modified: String,
    pub vuln_status: String,
    pub description: String,

    //simplify the rest
    pub cvss_version: String,
    pub cvss_vector: String,
    pub cvss_base_severity: String,
    pub cvss_base_score: f64,
    pub exploitability_score: f64,
    pub impact_score: f64,
    pub v2_fields: String,

    pub weaknesses: Vec<(String, String)>,
    // pub configurations: Vec<Vec<CPEMatch>>,
    pub references: Vec<References>,

    pub epss_score: f64,
    pub vulnerable_product: Vec<String>,
}

impl HasId for FilteredCVE {
    fn get_id(&self) -> &str {
        &self.id
    }
}

// Trait to enforce the presence of an `id` field
#[async_trait]
pub trait HasId {
    fn get_id(&self) -> &str;
}


#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct ExploitDB {
    id: String,
    pub file: String,
    pub description: String,
    pub date_published: String,
    pub author: String,
    pub r#type: String,
    pub platform: String,
    pub port: String,
    pub date_added: String,
    pub date_updated: String,
    pub verified: String,
    pub codes: String,
    pub tags: String,
    pub aliases: String,
    pub screenshot_url: String,
    pub application_url: String,
    pub source_url: String
}

impl HasId for ExploitDB {
    fn get_id(&self) -> &str {
        &self.id
    }
}



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EPSS {
    pub cve: String,
    pub epss: String,
    pub percentile: String,
    pub date: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct OTX {
    pub id: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub modified: Option<String>,
    pub published: Option<String>,

    // For optional arrays, we use Option<Vec<...>>
    pub references: Option<Vec<Reference>>,
    pub affected: Option<Vec<Affected>>,

    // If you'd like to rename a field in the struct, keep serde rename
    #[serde(rename = "schema_version")]
    pub schema_version: Option<String>,
}

// impl HasId for OTX {
//     fn get_id(&self) -> &str {
//         &self.id
//     }
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Affected {
    pub package: Option<Package>,
    pub ranges: Option<Vec<Range>>,

    #[serde(rename = "database_specific")]
    pub database_specific: Option<DatabaseSpecific>,

    // Versions might be omitted or empty in some advisories
    pub versions: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub name: Option<String>,
    pub ecosystem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub events: Option<Vec<Event>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseSpecific {
    pub source: Option<String>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct OSV {
    pub schema_version: String,
    pub id: String,
    pub modified: String,
    pub published: String,
    #[serde(default)]
    pub withdrawn: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub severity: Vec<Severity>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub references: Vec<Reference>,
    #[serde(default)]
    pub credits: Vec<Credit>,
    #[serde(default)]
    pub database_specific: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Severity {
    pub r#type: String,
    pub score: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Credit {
    pub name: String,
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub r#type: String,
}

#[derive(Clone, Debug)]
pub struct Sitemap {
    pub(crate) loc: String,
    pub(crate) lastmod: DateTime<FixedOffset>,
}

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ExploitDB {
    pub exploit_name: String,
    pub exploit_db_url: String,
    pub local_path: String,
    pub codes: String,
    pub verified: bool,
    pub file_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EPSS {
    pub cve: String,
    pub epss: String,
    pub percentile: String,
    pub date: String,
}


/// The name of the field `ID`.
pub const ID: &str = "id";

pub const OSV_TABLE_NAME: &str = "osv";
pub const OSV_DATA_COLUMN_NAME: &str = "data";

pub const GITHUB_OSV_REVIEWED_TABLE_NAME: &str = "github_reviewed";
pub const GITHUB_OSV_UNREVIEWED_TABLE_NAME: &str = "github_unreviewed";

// data is different from osv
pub const GITHUB_API_REVIEWED_TABLE_NAME: &str = "github_reviewed";
pub const GITHUB_API_UNREVIEWED_TABLE_NAME: &str = "github_unreviewed";

#[cfg(feature = "exploitdb")]
pub const EXPLOITDB_TABLE: &str = "exploit_db";

#[cfg(feature = "exploitdb")]
pub const EXPLOITDB_COLUMN: &str = "exploit_data";

/// The name of the database table for storing CVEs (Common Vulnerabilities and Exposures).
#[cfg(feature = "nvd")]
pub const CVE_TABLE: &str = "cves";

/// The name of the column for storing CVE identifiers in the `CVE_TABLE`.
#[cfg(feature = "nvd")]
pub const CVE_COLUMN: &str = "cve";

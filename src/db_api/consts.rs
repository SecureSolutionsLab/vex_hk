/// The name of the field `ID`.
pub const ID: &str = "id";

pub const OSV_TABLE: &str = "osv";

pub const OSV_COLUMN: &str = "osv_data";

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

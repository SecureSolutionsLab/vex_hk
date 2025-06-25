pub const TEMP_DIR_LOCATION: &str = "/zmnt/";

pub const STATE_FILE_LOCATION: &str = "./status.json";

/// Temporary table name created during some operations
///
/// Only exists during transactions
pub const TEMP_TABLE_NAME: &str = "vex_tmp";

pub const ENABLE_OSV: bool = true;
pub const ENABLE_GITHUB_OSV: bool = true;
pub const USE_API_FOR_GITHUB_OSV: bool = true;
pub const ENABLE_GITHUB_API_REVIEWED: bool = true;
pub const ENABLE_GITHUB_API_UNREVIEWED: bool = true;

#[cfg(feature = "osv")]
pub mod osv {
    pub const OSV_TABLE_NAME: &str = "osv";

    pub const INDEX: &str = "https://osv.dev/sitemap_index.xml";
    pub const FULL_DATA_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities/all.zip";
}

#[cfg(feature = "github")]
pub mod github {
    pub mod repository {
        pub const URL: &str =
            "https://github.com/github/advisory-database/archive/refs/heads/main.zip";
        pub const COMMITS_URL: &str =
            "https://api.github.com/repos/github/advisory-database/commits";
        pub const FILES_URL: &str =
            "https://api.github.com/repos/github/advisory-database/contents/";

        pub const REVIEWED_TABLE_NAME: &str = "github_osv_reviewed";
        pub const UNREVIEWED_TABLE_NAME: &str = "github_osv_unreviewed";
        pub const UPDATE_THRESHOLD: usize = 200;
    }

    pub mod api {
        pub const URL: &str = "https://api.github.com/advisories";

        // data is different from osv
        pub const REVIEWED_TABLE_NAME: &str = "github_api_reviewed";
        pub const UNREVIEWED_TABLE_NAME: &str = "github_api_unreviewed";

        // initial population
        pub const INCOMPLETE_REVIEWED_TABLE_NAME: &str = "github_api_incomp_reviewed";
        pub const INCOMPLETE_UNREVIEWED_TABLE_NAME: &str = "github_api_incomp_unreviewed";
    }
}

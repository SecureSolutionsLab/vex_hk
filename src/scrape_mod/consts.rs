pub(crate) const TOTAL_THREADS: u32 = 10;

#[cfg(feature = "exploitdb")]
mod exploitdb {
    /// File retrieved from searchsploit
    pub const FILE_EXPLOIT_LOCATION: &str = "src/resources/files_exploits.csv";

    pub const SEARCHSPLOIT_FILE_LOCATION: &str = "/opt/exploitdb/files_exploits.csv";

    pub const NEW_FILE_EXPLOIT: &str = "src/resources/files_exploits_new.csv";

    pub const USER_PASSWORD: &str = "<USER_PASSWORD>";
}
#[cfg(feature = "exploitdb")]
pub(crate) use exploitdb::{
    FILE_EXPLOIT_LOCATION, NEW_FILE_EXPLOIT, SEARCHSPLOIT_FILE_LOCATION, USER_PASSWORD,
};

#[cfg(feature = "nvd")]
mod nvd {
    ///API KEY for NVD
    pub const API_KEY_NVD: &str = "<API_KEY>";

    pub const TOTAL_PAGE: u32 = 2000;

    /// sleep NVD connection limit (ms)
    pub const SERVICE_SLEEP: u64 = 10000;

    pub const MIN_RESULTS_PER_THREAD: u32 = 2000;
}
#[cfg(feature = "nvd")]
pub(crate) use nvd::{API_KEY_NVD, MIN_RESULTS_PER_THREAD, SERVICE_SLEEP, TOTAL_PAGE};

#[cfg(feature = "osv")]
mod osv {
    pub const OSV_INDEX: &str = "https://osv.dev/sitemap_index.xml";

    pub const OSV_TIMESTAMP: &str = "last_timestamp_osv";

    pub const OSV_BATCH_SIZE: usize = 500;
}
#[cfg(feature = "osv")]
pub(crate) use osv::{OSV_BATCH_SIZE, OSV_INDEX, OSV_TIMESTAMP};

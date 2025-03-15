///API KEY for NVD
pub(crate) const API_KEY_NVD: &str = "<API_KEY>";

pub(crate) const TOTAL_PAGE: u32 = 2000;
pub(crate) const TOTAL_THREADS: u32 = 10;

/// sleep NVD connection limit (ms)
pub(crate) const SERVICE_SLEEP: u64 = 10000;

pub(crate) const MIN_RESULTS_PER_THREAD: u32 = 2000;

/// File retrieved from searchsploit
pub(crate) const FILE_EXPLOIT_LOCATION: &str = "src/resources/files_exploits.csv";

pub(crate) const SEARCHSPLOIT_FILE_LOCATION: &str = "/opt/exploitdb/files_exploits.csv";

pub(crate) const NEW_FILE_EXPLOIT: &str = "src/resources/files_exploits_new.csv";

pub(crate) const USER_PASSWORD: &str = "<USER_PASSWORD>";

pub(crate) const OSV_INDEX: &str = "https://osv.dev/sitemap_index.xml";

pub(crate) const OSV_TIMESTAMP: &str = "last_timestamp_osv";

pub(crate) const OSV_BATCH_SIZE: usize = 500;

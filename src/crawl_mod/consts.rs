///API KEY for NVD
pub(crate) const API_KEY_NVD: &str = "762c291f-d428-4e0a-8817-e25d3e5c854f";
// old keys "a92e0300-41c1-4197-9056-95fdd61af657";
pub(crate) const TOTAL_PAGE: u32 = 2000;
pub(crate) const TOTAL_THREADS: u32 = 10;

/// sleep NVD connection limit (ms)
pub(crate) const SERVICE_SLEEP: u64 = 10000;

/// NVD limits 50 requests with API to which a delay is required to send more requests
pub(crate) const MAX_REQUESTS_API: usize = 50;

pub(crate) const MIN_RESULTS_PER_THREAD: u32 = 2000;

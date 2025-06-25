use const_format::formatcp;

mod full;
mod update;

pub use full::manual_download_and_save_state;
pub use update::manual_update_and_save_state;

const TMP_DOWNLOAD_FILE_NAME: &str = "osv_all_tmp.zip";
const TMP_CSV_FILE_NAME: &str = "osv_tmp.csv";

const TMP_TABLE_NAME: &str = "vex_hk_osv_tmp";

// example id: ALBA-2019:0973
// the specification does not specify a max character limit for the value of an id
// some of these can get quite big (ex. BIT-grafana-image-renderer-2022-31176)
const OSV_ID_MAX_CHARACTERS: usize = 48;
const OSV_ID_SQL_TYPE: &str = formatcp!("character varying({})", OSV_ID_MAX_CHARACTERS);

/// Custom error type for `fetch_osv_details`.
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Failed to parse HTML: {0}")]
    Html(String),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JSON Data URL not found in HTML.")]
    MissingJsonUrl,
}

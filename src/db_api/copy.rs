use std::path::Path;

use sqlx::PgConnection;

/// Copy CSV contents to table, error on conflict
pub async fn execute_read_file_and_copy_to_table(
    conn: &mut PgConnection,
    table_name: &str,
    file_path: &Path,
) -> Result<u64, sqlx::Error> {
    log::debug!("Opening file {file_path:?} and copying contents to table {table_name:?} (error on conflict)");
    let mut copy_conn = conn
        .copy_in_raw(&format!(
            "COPY \"{table_name}\" FROM STDIN (FORMAT csv, DELIMITER ',')"
        ))
        .await?;
    let file = tokio::fs::File::open(file_path).await?;
    copy_conn.read_from(file).await?;

    let result = copy_conn.finish().await?;
    log::debug!("Copy connection result: {result}");
    Ok(result)
}

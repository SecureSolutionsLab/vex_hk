use sqlx::{Executor, PgConnection};

/// Create tmp table to be like some other table
///
/// To be used in transactions, table is dropped on commit (or if the commit fails)
pub async fn execute_create_tmp_table_drop_on_commit(
    conn: &mut PgConnection,
    new_table_name: &str,
    copy_settings_from_table_name: &str,
) -> Result<(), sqlx::Error> {
    log::debug!("Creating temporary table with name {new_table_name}, with setting copied from {copy_settings_from_table_name}");
    let query_str = format!(
        "
CREATE TEMP TABLE \"{new_table_name}\" 
(LIKE \"{copy_settings_from_table_name}\" INCLUDING DEFAULTS)
ON COMMIT DROP;
        "
    );
    conn.execute(sqlx::query(&query_str)).await?;
    Ok(())
}

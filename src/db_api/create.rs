use sqlx::{Executor, PgConnection};

/// Create tmp table to be like some other table
///
/// To be used in transactions, table is dropped on commit (or if the commit fails)
pub async fn execute_create_tmp_table_drop_on_commit(
    conn: &mut PgConnection,
    new_table_name: &str,
    copy_settings_from_table_name: &str,
) -> Result<(), sqlx::Error> {
    log::debug!("Creating temporary table");
    let query_str = format!(
        "
CREATE TEMP TABLE \"{}\" 
(LIKE \"{}\" INCLUDING DEFAULTS)
ON COMMIT DROP;
        ",
        new_table_name, copy_settings_from_table_name
    );
    conn.execute(sqlx::query(&query_str)).await?;
    Ok(())
}

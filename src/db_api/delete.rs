use crate::scrape_mod::structs::HasId;
use log::{error, info};
use sqlx::{Executor, PgConnection, Pool, Postgres};
use std::time::Instant;

/// Removes entries from the specified database table based on matching IDs.
///
/// This function deletes rows from a given table in the database where the value in the specified
/// column matches the ID of the provided entries. It can be used generically for any struct that
/// implements the `HasId` trait.
///
/// # Parameters
/// - `db`: A reference to the `Pool<Postgres>` database connection pool.
/// - `table`: The name of the table from which entries will be removed.
/// - `column`: The name of the column containing the JSONB field to match against.
/// - `field`: The specific key within the JSONB column to match (e.g., "id").
/// - `entries`: A slice of generic structs implementing the `HasId` trait.
///
/// # Returns
/// - `Ok(())` if the entries were successfully removed.
/// - `Err(sqlx::Error)` if an error occurs during the deletion process.
///
/// # Example
/// ```no_run
/// let entries = vec![
///     MyStruct { id: "123".to_string(), other_field: "example".to_string() },
///     MyStruct { id: "456".to_string(), other_field: "example2".to_string() },
/// ];
///
/// remove_entries_id(&db, "my_table", "data", "id", &entries).await?;
/// ```
pub async fn remove_entries_id<T>(
    db: &Pool<Postgres>,
    table: &str,
    column: &str,
    field: &str,
    entries: &[T],
) -> Result<(), sqlx::Error>
where
    T: HasId + Sync + Send,
{
    let instant = Instant::now();

    let ids: Vec<String> = entries.iter().map(|e| e.get_id().to_string()).collect();

    let sql_query = format!("DELETE FROM {table} WHERE {column}->>'{field}' = ANY($1)");

    let result = sqlx::query(&sql_query).bind(&ids).execute(db).await;

    match result {
        Ok(_) => {
            info!(
                "Deleted {} entries from {} in {:.2?}",
                ids.len(),
                table,
                instant.elapsed()
            );
            Ok(())
        }
        Err(e) => {
            error!("Error removing {} entries from {}: {}", ids.len(), table, e);
            Err(e)
        }
    }
}

/// Delete rows by id by pasting those ids in a query
pub async fn execute_delete_entries_by_id_slow(
    conn: &mut PgConnection,
    table_name: &str,
    // using values other than string requires that they live long enough for the query to be executed
    ids_to_delete: &[&str],
) -> Result<usize, sqlx::Error> {
    log::debug!("Deleting entries with bound query. Table: {table_name}");
    let query_str = format!("DELETE FROM {table_name} WHERE id = ANY($1)");
    let query = sqlx::query(&query_str).bind(ids_to_delete);
    let result = conn.execute(query).await?;
    Ok(result.rows_affected() as usize)
}

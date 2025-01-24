use crate::scrape_mod::structs::FilteredCVE;
use log::{error, info};
use sqlx::{Pool, Postgres};
use std::time::Instant;
use crate::db_api::utils::{execute_query_data};

/// Removes entries from the specified database table based on matching CVE IDs.
///
/// This function deletes rows from a given table in the database where the value in the specified
/// column matches the ID of the provided CVEs. It is primarily used to update or clean the database
/// before inserting new CVE data.
///
/// # Parameters
/// - `db`: A reference to the `Pool<Postgres>` database connection pool.
/// - `table`: The name of the table from which entries will be removed.
/// - `column`: The name of the column containing the JSONB field to match against.
/// - `field`: The specific key within the JSONB column to match (e.g., "id").
/// - `cves`: A vector of `FilteredCVE` objects whose IDs will be used for deletion.
///
/// # Returns
/// - `Ok(())` if the entries were successfully removed.
/// - `Err(sqlx::Error)` if an error occurs during the deletion process.
///
/// # Errors
/// This function propagates database errors to the caller for handling.
///
/// # Example
/// ```no_run
/// use sqlx::Pool;
/// use sqlx::Postgres;
///
/// let db: Pool<Postgres> = /* get your database connection pool */;
/// let table = "cves";
/// let column = "cve";
/// let field = "id";
/// let cves = vec![
///     FilteredCVE { id: "CVE-2024-12345".to_string(), /* other fields */ },
///     FilteredCVE { id: "CVE-2024-67890".to_string(), /* other fields */ },
/// ];
///
/// match remove_entries_id(&db, table, column, field, &cves).await {
///     Ok(_) => println!("Entries successfully removed."),
///     Err(e) => eprintln!("Failed to remove entries: {}", e),
/// }
/// ```
pub async fn remove_entries_id(
    db: &Pool<Postgres>,
    table: &str,
    column: &str,
    field: &str,
    cves: &Vec<FilteredCVE>,
) -> Result<(), sqlx::Error> {
    let instant = Instant::now();
    let mut id_vec = vec![];
    let sql_query = format!(
        "DELETE FROM {} WHERE {}->>'{}' = ANY($1)",
        table, column, field
    );
    for cve in cves {
        id_vec.push(cve.id.to_string());
    }
    let result = match execute_query_data(db, &*sql_query, &id_vec).await
    {
        Ok(result) => result,
        Err(e) => {
            error!("error removing {} data entries - error {}", cves.len(), e);
            return Err(e);
        }
    };
    info!(
        "database deletion {:.2?}, size {} {:?}",
        instant.elapsed(),
        cves.len(),
        result
    );
    Ok(())
}

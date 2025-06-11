use log::{error, info};
use serde_json::Value;
use sqlx::{postgres::PgRow, query, Error, PgPool, Row};
use std::fmt::Debug;

#[cfg(feature = "nvd")]
use std::time::Instant;

use crate::db_api::db_connection::get_db_connection;

/// Counts the total number of entries in the given database table.
///
/// This function establishes a database connection and queries the specified table to
/// count the total number of entries. If an error occurs during connection or query
/// execution, it logs the error and returns `0`.
///
/// # Arguments
/// - `table_name`: The name of the database table to count records from.
///
/// # Returns
/// - The total number of entries in the specified table as `i64`.
/// - Returns `0` if an error occurs.
///
/// # Behavior
/// - Constructs and executes an SQL query dynamically:
///   ```sql
///   SELECT count(*) FROM table_name;
///   ```
/// - Logs an error if the query returns more than one result, which is unexpected.
///
/// # Errors
/// - Logs an error if the database connection fails or the query execution fails.
///
/// # Example
/// ```no_run
/// let count = count_table_entries("cves").await;
/// println!("Total entries in table: {}", count);
/// ```
pub async fn count_table_entries(table_name: &str) -> i64 {
    let db_conn = match get_db_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Error in database connection: {}", e);
            return 0;
        }
    };

    // Build the SQL query dynamically
    let query_str = format!("SELECT count(*) AS count FROM {};", table_name);

    let query_db = match query(&query_str).fetch_all(&db_conn).await {
        Ok(query_result) => query_result,
        Err(e) => {
            error!("Error in querying database for table {}: {}", table_name, e);
            return 0;
        }
    };

    // Ensure that only a single result is returned
    if query_db.len() != 1 {
        error!(
            "Unexpected query result count for table {}: {}",
            table_name,
            query_db.len()
        );
        return 0;
    }

    // Extract and return the count from the query result
    match query_db.get(0).unwrap().try_get::<i64, _>("count") {
        Ok(count) => {
            info!(
                "Successfully counted {} entries in table {}",
                count, table_name
            );
            count
        }
        Err(e) => {
            error!("Failed to extract count from query result: {}", e);
            0
        }
    }
}

/// Verifies if a specific CVE ID exists in the database.
///
/// This function checks if a CVE with the given ID exists in the `cves` table.
/// It performs a query to count the number of entries with the specified CVE ID.
///
/// # Parameters
/// - `id`: The ID of the CVE to verify.
///
/// # Returns
/// - `true`: If exactly one entry or multiple entries with the given ID exist.
/// - `false`: If no entry exists or an error occurs during the query.
///
/// # Behavior
/// - Executes the SQL query:
///   ```sql
///   SELECT count(*) FROM cves WHERE cve->>'id' = $1;
///   ```
/// - If more than one entry exists, logs a warning but still returns `true`.
/// - Logs an error if the database connection fails.
///
/// # Example
/// ```no_run
/// let id = "CVE-2024-1234";
/// let exists = _verify_cve_db(id).await;
/// if exists {
///     println!("CVE {} exists in the database.", id);
/// } else {
///     println!("CVE {} does not exist in the database.", id);
/// }
/// ```
///
/// # Note
/// This function performs a slow operation due to the nature of the query. Use
/// it sparingly, especially for large datasets.
pub async fn _verify_cve_db(id: &str) -> bool {
    let db_conn = match get_db_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("error in connection {}", e);
            return false;
        }
    };
    let query_db_size = query("select count(*) from cves where cve->>'id' = $1;")
        .bind(id)
        .fetch_all(&db_conn)
        .await
        .unwrap();
    let count: i64 = query_db_size.get(0).unwrap().get("count");
    if count == 1 {
        return true;
    } else if count > 1 {
        println!("too many entries for {}", id);
        return true;
    }
    false
}

/// Verifies the database for repeated CVE entries.
///
/// This function checks for duplicate CVE entries in the `cves` table by grouping
/// CVEs by their IDs and identifying those with a count greater than one. It logs
/// the time taken to perform the operation and returns the number of duplicate entries.
///
/// # Returns
/// - The number of duplicate CVE entries as `usize`.
/// - Returns `0` if the database connection fails.
///
/// # Behavior
/// - Executes the SQL query:
///   ```sql
///   SELECT cve->'id' AS cve_id, COUNT(*)
///   FROM cves
///   GROUP BY cve->'id'
///   HAVING COUNT(*) > 1;
///   ```
/// - Logs the execution time and the number of duplicate entries.
///
/// # Errors
/// - Logs an error and returns `0` if the database connection fails.
///
/// # Example
/// ```no_run
/// let duplicates = verify_database().await;
/// println!("Number of duplicate CVEs: {}", duplicates);
/// ```
///
/// # Performance
/// This function may take considerable time for large datasets, as it involves
/// grouping and counting operations on the entire `cves` table.
#[cfg(feature = "nvd")]
pub async fn verify_database() -> usize {
    let instant = Instant::now();
    let db = match get_db_connection().await {
        Ok(db) => db,
        Err(_) => return 0,
    };
    // let query = query("SELECT * FROM cves WHERE cve IN (SELECT cve FROM cves GROUP BY cve HAVING COUNT(*) > 1);").fetch_all(&db).await.unwrap();
    let query = query(
        "SELECT cve->'id' AS cve_id, COUNT(*) FROM cves GROUP BY cve->'id' HAVING COUNT(*) > 1;",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    println!(
        "database verification {:.2?}, size {}",
        instant.elapsed(),
        query.len()
    );
    query.len()
}

/// Compares input entries (provided as JSON data) with records in the specified table and column,
/// returning the status of each entry in a generic row type.
///
/// The input JSON is expected to be an array of objects that can be interpreted as a recordset with
/// fields `id` (text) and `modified` (timestamptz). For each input record, the function performs:
///
/// - If the record in `{table}` (by matching `{column}->>'id'`) does not exist, returns `"Entry does not exist"`.
/// - If the input record's `modified` timestamp is more recent than the stored record's modified timestamp,
///   returns `"Input is more recent"`.
/// - Otherwise, returns `"Entry exists but is up-to-date"`.
///
/// # Generic Parameters
///
/// * `T` - The output row type that must implement `sqlx::FromRow<'_, PgRow>`. Typically, this type
///         would have fields such as `id: String` and `status: String` corresponding to the query output.
///
/// # Arguments
///
/// * `db_conn` - A reference to the PostgreSQL connection pool.
/// * `table` - The name of the database table containing the records.
/// * `column` - The name of the JSON column in the table holding the record data.
/// * `data` - A `serde_json::Value` representing the input data (a JSON array of objects with `id` and `modified` fields).
///
/// # Returns
///
/// Returns a `Result` containing a vector of `T` if the query executes successfully, or an `Error` if it fails.
///
/// # Errors
///
/// This function returns an error if:
/// - The query fails to execute.
/// - The database connection encounters an error.
///
/// # Example
///
/// ```rust,no_run
/// # use sqlx::PgPool;
/// # use serde_json::json;
/// # #[derive(Debug, sqlx::FromRow)]
/// # struct EntryStatus {
/// #     id: String,
/// #     status: String,
/// # }
/// # async fn example(db_conn: PgPool) -> Result<(), sqlx::Error> {
/// let data = json!([
///     { "id": "CVE-2024-26256", "modified": "2025-02-21T00:00:00+00:00" },
///     { "id": "CVE-2020-8698", "modified": "2025-01-15T12:00:00+00:00" }
/// ]);
///
/// let statuses: Vec<EntryStatus> = find_missing_or_stale_entries_by_id(&db_conn, "osv", "osv_data", data).await?;
/// for status in statuses {
///     println!("ID: {}, Status: {}", status.id, status.status);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn find_missing_or_stale_entries_by_id<T>(
    db_conn: &PgPool,
    table: &str,
    column: &str,
    data: Value,
) -> Result<Vec<T>, Error>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin + Debug,
{
    let query = format!(
        r#"
WITH input AS (
    SELECT *
    FROM jsonb_to_recordset($1::jsonb)
    AS x(id text, modified timestamptz)
)
SELECT
    input.id,
    CASE
        WHEN {table}.{column} IS NULL THEN 'Entry does not exist'
        WHEN input.modified > ({table}.{column}->>'modified')::timestamptz THEN 'Input is more recent'
        ELSE 'Entry exists but is up-to-date'
    END AS status
FROM input
LEFT JOIN {table} ON {table}.{column}->>'id' = input.id;
        "#,
        table = table,
        column = column
    );

    let statuses = sqlx::query_as::<_, T>(&query)
        .bind(data)
        .fetch_all(db_conn)
        .await?;

    info!("Query returned statuses: {:?}", statuses);
    Ok(statuses)
}

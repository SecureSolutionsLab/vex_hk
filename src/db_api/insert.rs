use crate::db_api::{db_connection::get_db_connection, utils::execute_query_data};
use log::{error, info};
use serde_json::json;
use sqlx::{query, Error, Executor, PgConnection, PgPool};
use std::time::Instant;

#[cfg(feature = "nvd")]
use crate::scrape_mod::structs::{CPEMatch, FilteredCVE};

/// Inserts data into a database table sequentially.
///
/// This function performs sequential database insertions for a list of serialized
/// objects. Each object is converted to JSON and inserted into the specified table
/// and column. Sequential insertion means each record is inserted one at a time.
///
/// # Parameters
/// - `table`: The name of the database table where the data will be inserted.
/// - `column`: The column in the table where the data will be inserted.
/// - `cve`: A vector of serializable objects to be inserted.
///
/// # Returns
/// - `Ok(())`: If all insertions complete successfully.
/// - `Err(sqlx::Error)`: If an error occurs during database connection or insertion.
///
/// # Behavior
/// - Converts each object in `cve` into JSON using `serde_json::json!`.
/// - Constructs an SQL query in the form:
///   ```sql
///   INSERT INTO table(column) SELECT UNNEST($1::jsonb[]);
///   ```
/// - Logs the result of each insertion attempt.
///
/// # Example
/// ```no_run
/// let cve_data = vec![CVE { id: "CVE-2024-1234".to_string() }];
/// _insert_db_sequential("cve_table", "data", cve_data).await.unwrap();
/// ```
///
/// # Performance
/// - Logs the total execution time and the size of the inserted data.
///
/// # Limitations
/// - Sequential insertions are slower compared to batch insertions.
/// - Use for small datasets or when immediate feedback for each record is required.
pub async fn _insert_db_sequential<T: serde::Serialize>(
    table: &str,
    column: &str,
    cve: Vec<T>,
) -> Result<(), Error> {
    let instant = Instant::now();
    let db = get_db_connection().await?;
    let sql_query = format!("INSERT INTO {table}({column}) SELECT UNNEST($1::jsonb[])");
    for value in &cve {
        let json_cve = json!(value);
        match query(&sql_query).bind(&json_cve).execute(&db).await {
            Ok(result) => {
                info!("Inserted CVE {result:?}")
            }
            Err(_) => {
                error!("Issue executing sequential insertion")
            }
        };
    }
    info!(
        "database insertion {:.2?}, size {}",
        instant.elapsed(),
        cve.len(),
    );
    Ok(())
}

/// Inserts data into a database table in parallel.
///
/// This function performs a batch insertion of serialized objects into the specified
/// table and column. The data is converted to JSON and sent as a single SQL query.
///
/// # Parameters
/// - `db_conn`: A reference to the PostgreSQL connection pool.
/// - `table`: The name of the database table where the data will be inserted.
/// - `column`: The column in the table where the data will be inserted.
/// - `data`: A reference to a vector of serializable objects to be inserted.
///
/// # Returns
/// - `Ok(())`: If the batch insertion completes successfully.
/// - `Err(sqlx::Error)`: If an error occurs during the query execution.
///
/// # Behavior
/// - Converts all objects in `data` to JSON using `serde_json::json!`.
/// - Constructs an SQL query in the form:
///   ```sql
///   INSERT INTO table(column) SELECT UNNEST($1::jsonb[]);
///   ```
/// - Executes the insertion in a single query.
///
/// # Example
/// ```no_run
/// let cve_data = vec![CVE { id: "CVE-2024-1234".to_string() }];
/// insert_parallel(&db_conn, "cve_table", "data", &cve_data).await.unwrap();
/// ```
///
/// # Advantages
/// - More efficient than sequential insertion for large datasets.
///
/// # Limitations
/// - The entire dataset must fit into memory.
pub async fn insert_parallel<T: serde::Serialize>(
    db_conn: &PgPool,
    table: &str,
    column: &str,
    data: &[T],
) -> Result<(), Error> {
    let sql_query = format!("INSERT INTO {table}({column}) SELECT UNNEST($1::jsonb[])");
    let submit_data: Vec<_> = data.iter().map(|cve| json!(cve)).collect();
    execute_query_data(db_conn, &sql_query, &submit_data).await?;
    Ok(())
}

// same as insert_parallel but data is already json
// todo: experimental
pub async fn insert_parallel_json(
    db_conn: &PgPool,
    table: &str,
    column: &str,
    data: &[serde_json::Value],
) -> Result<(), Error> {
    let sql_query = format!("INSERT INTO {table}({column}) SELECT UNNEST($1::jsonb[])");
    execute_query_data(db_conn, &sql_query, data).await?;
    Ok(())
}

// same as above but insert json data already converted into strings
// database should send back an error if json is badly converted
// todo: experimental
pub async fn insert_parallel_string_json(
    db_conn: &PgPool,
    table: &str,
    column: &str,
    data: &[&str],
) -> Result<(), Error> {
    let sql_query = format!("INSERT INTO {table}({column}) SELECT UNNEST($1::jsonb[])");
    execute_query_data(db_conn, &sql_query, data).await?;
    Ok(())
}

/// Inserts CVE data and associated configurations into the database.
///
/// This function performs batch insertions for CVEs and their associated configurations.
/// It first inserts CVE data into a specified table, then inserts the configurations
/// into a separate `configurations` table.
///
/// # Parameters
/// - `db_conn`: A reference to the PostgreSQL connection pool.
/// - `table`: The name of the database table where CVEs will be inserted.
/// - `column`: The column in the table where CVEs will be inserted.
/// - `cves`: A reference to a vector of `FilteredCVE` objects to be inserted.
/// - `configuration`: A vector of tuples containing CVE IDs and their configurations.
///
/// # Returns
/// - `Ok(())`: If all insertions complete successfully.
/// - `Err(sqlx::Error)`: If an error occurs during the query execution.
///
/// # Behavior
/// - Converts `cves` and `configuration` data to JSON.
/// - Inserts CVEs using the [`insert_parallel`] function.
/// - Inserts configurations into the `configurations` table with a custom query:
///   ```sql
///   INSERT INTO configurations(cveid, configuration)
///   SELECT vec.cve_id, vec.config
///   FROM UNNEST($1::text[], $2::jsonb[]) AS vec(cve_id, config);
///   ```
///
/// # Example
/// ```no_run
/// let cves = vec![FilteredCVE { id: "CVE-2024-1234".to_string() }];
/// let configurations = vec![
///     ("CVE-2024-1234".to_string(), vec![vec![CPEMatch::default()]])
/// ];
/// insert_parallel_cve(&db_conn, "cve_table", "data", &cves, configurations).await.unwrap();
/// ```
///
/// # Advantages
/// - Combines batch insertion for CVEs and their configurations.
/// - Efficient for handling large datasets.
///
/// # Limitations
/// - Requires memory to store all data before insertion.
// todo: nvd dependent (breaks compilation otherwise)
#[cfg(feature = "nvd")]
pub async fn insert_parallel_cve(
    db_conn: &PgPool,
    table: &str,
    column: &str,
    cves: &Vec<FilteredCVE>,
    configuration: Vec<(String, Vec<Vec<CPEMatch>>)>,
) -> Result<(), sqlx::Error> {
    let mut submit_cve = vec![];
    let mut submit_cveid = vec![];
    let mut submit_configuration = vec![];
    for cve in cves {
        submit_cve.push(json!(cve))
    }
    for (cveid, configuration) in configuration {
        submit_cveid.push(cveid);
        submit_configuration.push(json!(configuration));
    }

    let _ = insert_parallel(db_conn, table, column, &submit_cve).await?;

    let _ = query!(
        "insert into configurations(cveid, configuration) select vec.cve_id, vec.config from unnest($1::text[], $2::jsonb[]) AS vec(cve_id, config)", &submit_cveid,
        &submit_configuration)
        .execute(db_conn)
        .await?;
    Ok(())
}

pub async fn execute_insert_from_one_table_to_another(
    conn: &mut PgConnection,
    from_table_name: &str,
    to_table_name: &str,
) -> Result<(), sqlx::Error> {
    log::debug!("Inserting all entries from table {from_table_name} to {to_table_name}");
    let query_str = format!("INSERT INTO {to_table_name} SELECT * FROM {from_table_name};");
    let query = sqlx::query(&query_str);
    conn.execute(query).await?;
    Ok(())
}

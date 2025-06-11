use sqlx::{Error, Pool, Postgres};

/// Executes a parameterized SQL query with data bound as an array.
///
/// This function takes a SQL query and a vector of data, binds the data as an array
/// to the query, and executes it against the provided PostgreSQL connection pool.
/// It returns the number of rows affected by the query.
///
/// # Parameters
/// - `db`: A reference to the PostgreSQL connection pool.
/// - `sql_query`: The SQL query string with placeholders for parameters.
/// - `data`: A reference to a vector of data to bind to the query. The data is passed
///   as an array parameter to the SQL query.
///
/// # Returns
/// - `Ok(u64)`: The number of rows affected by the query.
/// - `Err(sqlx::Error)`: If an error occurs during query execution.
///
/// # Requirements
/// - `T`: The type of the elements in the `data` vector must:
///   - Be a valid PostgreSQL type (`sqlx::Type<Postgres>`).
///   - Be encodable (`sqlx::Encode<'q, Postgres>`).
///   - Support array operations (`sqlx::postgres::PgHasArrayType`).
///   - Be `Send` and `Sync` for asynchronous execution.
///
/// # Example
/// ```no_run
/// let db: Pool<Postgres> = get_db_connection().await.unwrap();
/// let data = vec!["value1", "value2", "value3"];
/// let query = "INSERT INTO my_table (my_column) SELECT UNNEST($1::text[])";
/// let rows_affected = execute_query_data(&db, query, &data).await.unwrap();
/// println!("Rows affected: {}", rows_affected);
/// ```
///
/// # Behavior
/// - Executes the query using the `sqlx::query` API.
/// - Binds the `data` vector as a single array parameter to the query.
///
/// # Errors
/// - Returns an error if the query fails or the data cannot be bound.
pub async fn execute_query_data<'q, T>(
    db: &Pool<Postgres>,
    sql_query: &'q str,
    data: &'q [T],
) -> Result<u64, Error>
where
    T: sqlx::Type<Postgres>
        + sqlx::Encode<'q, Postgres>
        + Send
        + Sync
        + sqlx::postgres::PgHasArrayType, // Ensure compatibility with `sqlx::query`
{
    let result = sqlx::query(sql_query).bind(data).execute(db).await?;
    Ok(result.rows_affected())
}

/// Executes a raw SQL query and returns the number of rows affected.
///
/// This function takes a SQL query string, executes it against the provided PostgreSQL
/// connection pool, and returns the number of rows affected.
///
/// # Parameters
/// - `db`: A reference to the PostgreSQL connection pool.
/// - `query`: The raw SQL query string to be executed.
///
/// # Returns
/// - `Ok(u64)`: The number of rows affected by the query.
/// - `Err(sqlx::Error)`: If an error occurs during query execution.
///
/// # Example
/// ```no_run
/// let db: Pool<Postgres> = get_db_connection().await.unwrap();
/// let query = "DELETE FROM my_table WHERE my_column = 'value'";
/// let rows_affected = _execute_query(&db, query).await.unwrap();
/// println!("Rows affected: {}", rows_affected);
/// ```
///
/// # Behavior
/// - Executes the query using the `sqlx::query` API.
/// - Does not bind any parameters; the query must be fully constructed.
///
/// # Errors
/// - Returns an error if the query fails or the database connection is invalid.
///
/// # Note
/// This function should be used with caution for queries that are not parameterized,
/// as they might be vulnerable to SQL injection. Always sanitize input to ensure safety.
pub async fn _execute_query(db: &Pool<Postgres>, query: &str) -> Result<u64, Error> {
    let result = sqlx::query(query).execute(db).await?;
    Ok(result.rows_affected())
}

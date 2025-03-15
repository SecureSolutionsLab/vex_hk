use dotenv::dotenv;
use log::error;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::env;

/// Retrieves the database connection string from environment variables.
///
/// This function uses the `dotenv` crate to load environment variables
/// from a `.env` file (if it exists) and then fetches the `DATABASE_URL`
/// environment variable. If the variable is not found, it logs an error
/// and panics.
///
/// # Panics
/// Panics if the `DATABASE_URL` environment variable is not set.
///
/// # Example
/// ```no_run
/// let db_url = get_db();
/// println!("Database URL: {}", db_url);
/// ```
///
/// # Dependencies
/// - `dotenv` for loading environment variables from a `.env` file.
/// - `env` for accessing environment variables.
pub fn get_db() -> String {
    dotenv().ok();
    env::var("DATABASE_URL").unwrap_or_else(|error| {
        error!("error in retrieving db {}", error);
        panic!("db retrieval")
    })
}

/// Asynchronously creates a database connection pool.
///
/// This function initializes a connection pool to the database specified
/// by the connection string retrieved from [`get_db`]. It uses the `sqlx`
/// library to manage the connection pool.
///
/// # Returns
/// - `Ok(Pool<Postgres>)`: A successfully created connection pool.
/// - `Err(sqlx::Error)`: If there is an error establishing the connection.
///
/// # Errors
/// This function will return an error if:
/// - The connection string retrieved from [`get_db`] is invalid.
/// - The database is unreachable.
///
/// # Example
/// ```no_run
/// use sqlx::postgres::PgPoolOptions;
/// use your_crate::get_db_connection;
///
/// #[tokio::main]
/// async fn main() {
///     match get_db_connection().await {
///         Ok(pool) => println!("Database connection pool created successfully!"),
///         Err(e) => eprintln!("Failed to create database connection pool: {}", e),
///     }
/// }
/// ```
///
/// # Dependencies
/// - `sqlx` for managing database connections and connection pools.
/// - [`get_db`] for retrieving the database connection string.
pub async fn get_db_connection() -> Result<Pool<Postgres>, sqlx::Error> {
    PgPoolOptions::new().connect(&*get_db()).await
}

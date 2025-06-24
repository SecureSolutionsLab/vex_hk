use crate::utils::config::_file_exists;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
};

/// Creates a new environment file at the specified path.
///
/// This function creates an empty `.env` file at the given `file_path`.
/// If the file already exists, it will be overwritten.
///
/// # Parameters
/// - `file_path`: A string slice (`&str`) specifying the path where the `.env` file
///   should be created.
///
/// # Errors
/// - Panics if the file cannot be created (e.g., due to insufficient permissions
///   or invalid path).
///
/// # Example
/// ```no_run
/// _create_env_file(".env");
/// println!("Environment file created!");
/// ```
fn _create_env_file(file_path: &str) {
    File::create(file_path).unwrap();
}

/// Parses a single line from an environment file.
///
/// This function takes a line in the format `KEY=VALUE` and splits it into
/// a tuple `(String, String)`. Leading and trailing whitespace is trimmed
/// from both the key and value. Lines that do not contain a valid key-value
/// pair are ignored.
///
/// # Parameters
/// - `line`: A string slice (`&str`) representing a single line from the `.env` file.
///
/// # Returns
/// - `Some((String, String))`: If the line contains a valid key-value pair.
/// - `None`: If the line is invalid or improperly formatted.
///
/// # Example
/// ```
/// let line = "FOO=BAR";
/// if let Some((key, value)) = _parse_env_line(line) {
///     println!("Key: {}, Value: {}", key, value);
/// } else {
///     println!("Invalid environment line.");
/// }
/// ```
fn _parse_env_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
    } else {
        None
    }
}

/// Writes a new entry or updates an existing key-value pair in the `.env` file.
///
/// This function reads the contents of the `.env` file, updates the value for the
/// specified key if it exists, or appends a new key-value pair if it does not.
/// The `.env` file is created if it does not already exist.
///
/// # Parameters
/// - `key`: The key to write or update in the `.env` file.
/// - `value`: The value to associate with the key.
///
/// # Behavior
/// - If the `.env` file does not exist, it will be created.
/// - Reads the `.env` file line by line, parsing each line into key-value pairs.
/// - Updates the value for the specified key or inserts the key-value pair if
///   the key does not exist.
/// - Rewrites the entire `.env` file with the updated key-value pairs.
///
/// # Errors
/// - Panics if the `.env` file cannot be opened, read, or written to.
///
/// # Example
/// ```no_run
/// _write_env("DATABASE_URL", "postgres://user:password@localhost/db");
/// println!("Environment variable updated!");
/// ```
pub fn _write_env(key: &str, value: &str) {
    let env_file_path = ".env";
    if !_file_exists(env_file_path) {
        _create_env_file(env_file_path);
    }
    let file = File::open(env_file_path).unwrap();
    let reader = BufReader::new(file);

    let mut env_vars: HashMap<String, String> = HashMap::new();
    for line in reader.lines() {
        let line = line.unwrap();
        if let Some((key, value)) = _parse_env_line(&line) {
            env_vars.insert(key, value);
        }
    }
    env_vars.insert(key.to_string(), value.to_string());

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(env_file_path)
        .unwrap();

    for (key, value) in env_vars.iter() {
        writeln!(&mut file, "{key}={value}").unwrap();
    }
}

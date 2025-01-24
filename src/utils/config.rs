use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Location of the resources file
const FILE_PATH: &str = "src/resources/config.conf";

/// Config struct use to store key values
#[derive(Serialize, Deserialize)]
struct Config {
    map: HashMap<String, String>,
}

/// Reads the value for a given key from the configuration file.
///
/// This function attempts to read a configuration file located at `FILE_PATH`
/// and retrieve the value associated with the specified key. The file is
/// expected to be in JSON format.
///
/// # Parameters
/// - `key`: A `String` representing the key to look up in the configuration.
///
/// # Returns
/// - `Some(String)`: The value associated with the key, if it exists.
/// - `None`: If the file cannot be opened, read, or the key does not exist.
///
/// # Behavior
/// - Opens the configuration file at `FILE_PATH`.
/// - Parses the file contents as a JSON object into a `Config` struct.
/// - Looks up the specified key in the parsed configuration and returns the
///   associated value, if present.
///
/// # Errors
/// - Panics if the file contents cannot be read or parsed as valid JSON.
///
/// # Example
/// ```no_run
/// let value = read_config("example_key".to_string());
/// match value {
///     Some(v) => println!("Value: {}", v),
///     None => println!("Key not found or file missing"),
/// }
/// ```
pub fn read_config(key: String) -> Option<String> {
    let mut file = match OpenOptions::new().read(true).open(FILE_PATH) {
        Ok(file) => file,
        Err(_) => {
            return None;
        }
    };

    // Read the existing contents of the file
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let config: Config = match contents.len() {
        0 => Config {
            map: HashMap::new(),
        },
        _ => serde_json::from_str(&contents).expect("Failed to parse JSON"),
    };
    let value = config.map.get(&key);
    if value.is_some() {
        return Some(value.unwrap().to_owned());
    }
    println!("value does not exist");
    None
}

/// Stores a key-value pair in the configuration file.
///
/// This function writes the provided key and value to a configuration file
/// located at `FILE_PATH`. If the file already exists, it reads its current
/// contents, updates the key-value pair, and writes the updated contents back
/// to the file.
///
/// # Parameters
/// - `key`: A `String` representing the key to store.
/// - `value`: A `String` representing the value to associate with the key.
///
/// # Behavior
/// - Opens the configuration file at `FILE_PATH`, creating it if it does not exist.
/// - Reads the existing contents of the file and parses it as a JSON object.
/// - Updates the key-value pair in the parsed configuration or inserts it if
///   the key does not exist.
/// - Writes the updated configuration back to the file.
///
/// # Errors
/// - Panics if the file cannot be opened, read, or written to.
/// - Panics if the existing file contents cannot be parsed as valid JSON.
///
/// # Example
/// ```no_run
/// store_key("example_key".to_string(), "example_value".to_string());
/// ```
pub fn store_key(key: String, value: String) {
    // Read the existing config file or create a new one if it doesn't exist
    println!("store key: {}", FILE_PATH);
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open(FILE_PATH)
        .expect("Failed to open file");

    // Read the existing contents of the file
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    let mut config: Config = match contents.len() {
        0 => Config {
            map: HashMap::new(),
        },
        _ => serde_json::from_str(&contents).expect("Failed to parse JSON"),
    };

    config.map.insert(key, value);

    let serialized_config = serde_json::to_string(&config).expect("Failed to serialize JSON");

    // Move the file cursor to the beginning before writing
    file.seek(std::io::SeekFrom::Start(0))
        .expect("Failed to seek file");

    file.write_all(serialized_config.as_bytes())
        .expect("Failed to write file");
}


/// Checks if a file exists at the specified path.
///
/// This utility function checks for the existence of a file or directory at
/// the given file path.
///
/// # Parameters
/// - `file_path`: A string slice (`&str`) representing the path to the file or directory.
///
/// # Returns
/// - `true`: If the file or directory exists.
/// - `false`: If the file or directory does not exist.
///
/// # Example
/// ```no_run
/// if _file_exists("src/resources/config.conf") {
///     println!("File exists!");
/// } else {
///     println!("File does not exist.");
/// }
/// ```
pub fn _file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}


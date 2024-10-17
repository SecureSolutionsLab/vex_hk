pub mod tools {
    use std::collections::HashMap;
    use std::env;
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Seek, Write};
    use std::path::Path;

    use chrono::Utc;
    use dotenv::dotenv;
    use serde::{Deserialize, Serialize};

    /// Location of the resources file
    const FILE_PATH: &str = "src/resources/config.conf";

    /// Config struct use to store key values
    #[derive(Serialize, Deserialize)]
    struct Config {
        map: HashMap<String, String>,
    }

    /// Reads the value for a given key from the config file
    /// stored within the resources dir
    ///
    /// #Arguments
    /// * `key` - the
    ///
    /// #Returns
    /// * option<value> or none if it does not exist
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

    /// Store key values within a config file stored in the resources dir
    pub fn store_key(key: String, value: String) {
        // Read the existing config file or create a new one if it doesn't exist
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

    /// Converts the current time to datetime
    /// This follows the guides stipulated by NVD (Y-m-dTH:M:SZ)
    pub fn instant_to_datetime() -> String {
        let current_time = Utc::now();
        let formatted_date = current_time.format("%Y-%m-%dT%H:%M:%S%.3fZ");
        formatted_date.to_string()
    }

    /// Reads from the config file the timestamp for the last crawl
    /// Necessary to request new CVEs or update from NVD database
    pub fn get_timestamp() -> String {
        let value = read_config("last_timestamp".to_string());

        let timestamp = if value.is_none() {
            let local_timestamp = instant_to_datetime();
            store_key("last_timestamp".to_string(), local_timestamp.clone());
            local_timestamp
        } else {
            value.unwrap()
        };
        timestamp
    }

    /// Returns the db connection string
    pub fn get_db() -> String {
        dotenv().ok();
        match env::var("DATABASE_URL") {
            Ok(db) => db,
            Err(error) => {
                println!("error in retrieving db {}", error);
                panic!("db retrieval")
            }
        }
    }

    /// Writes a new entry or updates an existing value in the .env file
    pub fn _write_env(key: &str, value: &str) {
        let env_file_path = ".env";
        if !_file_exists(&env_file_path) {
            _create_env_file(&env_file_path);
        }
        let file = File::open(&env_file_path).unwrap();
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
            .open(&env_file_path)
            .unwrap();

        for (key, value) in env_vars.iter() {
            writeln!(&mut file, "{}={}", key, value).unwrap();
        }
    }

    /// Auxiliary function for _write_env
    fn _parse_env_line(line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() == 2 {
            Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
        } else {
            None
        }
    }

    /// Function to check if a file exists
    fn _file_exists(file_path: &str) -> bool {
        Path::new(file_path).exists()
    }

    /// Function to create an environment file
    fn _create_env_file(file_path: &str) {
        File::create(file_path).unwrap();
    }
}

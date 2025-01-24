# [VEx_HK] Vulnerability Exploit hunter killer

## What is VEx_HK?
VEx_HK is a scraper designed specifically to scrape Open Source Intelligence databases.
This retrieves the information from different sources, specifically for now NVD, OSV, AlienVault OTX, and ExploitDB, and stores it in a local PostgreSQL database.
The information is stored in the JSONB format in a key-value style, i.e., incrementing a monotonic counter for each entry.

First iteration of the scraper will retrieve the entirety of the databases indicated in the config file.
Additional databases can be added but require the addition of a parsing system and data handling.
The data can be added to the database through the provided API.

**Note:** Before uploading the data it is necessary to verify if the table is already present.

**Note 2:** For NVD, it is recommended to have a second table called "Configurations" for the CPE criteria. This is because, in the NVD crawler, we implemented a combinatorial method to generate the various combinations that might occur in the CPE and illustrate how the vulnerability manifests.

**Note 3** AlienVault OTX, takes about one hour for every request, so the first retrieval will be time costly. 

**Note 4** The [configuration file](./src/resources/config.conf) stores the timestamp used by the scraper to know the last time it retrieve the data. It can be used to store other types of information in a Key-Value manner.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Features](#features)
- [Licensing](#licensing)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

[//]: # (- [Citation]&#40;#citation&#41;)


## Prerequisites
Before starting, it is necessary to verify the following installations within the machine:
- Rustc 1.84.0
- PostgreSQL 16.3
- searchsploit
- Change the name of the db used in the .env file
- Provide the information of the tables (name and column) created for each database in the [`src/db_api/consts.rs`](./src/db_api/consts.rs) file.
- Provide the API tokens if the database requires in the [`src/scrape_mod/consts.rs`](./src/scrape_mod/consts.rs) file.

## Quickstart
To execute the source code, use the following command:

```bash
cargo run --package vex_hk --bin vex_hk
```

## Contributing
For additional databases additional scraper implementations are required.
Since every OSINT database uses its own schema a new file to retrieve the data and prepare it for local database submission is needed.


Submission to local database can be used through the [DB API](./src/db_api) folder where the API is defined.

API functions for DB operations are divided by file.

Current available interactions:
- [Delete](./src/db_api/delete.rs)
- [Insert](./src/db_api/insert.rs) (provides sequential and near-parallel insertion)
- [Db connection](./src/db_api/db_connection.rs)
- [Query db](./src/db_api/query_db.rs) 


## Licensing
[License](./LICENSE)

[//]: # (## Citation)

## Some database commands (PostgreSQL)
- Delete all entries and restart counter - `TRUNCATE TABLE <table_name> RESTART IDENTITY;`
- Create table with auto incrementing id - `CREATE TABLE <table_name> (<column_name> INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, <column_name> JSONB NOT NULL);`
- Create a database - `CREATE DATABASE <database_name>;`
- Selection - `Select <field> from <table_name>;`
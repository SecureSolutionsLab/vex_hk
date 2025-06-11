# 15/03/2025

- Reorganized scrapers into separate features. Individual scrapers should now not fail to compile because of misconfigured databases.
- OSV scraper now downloads and saves contents directly to a file using a stream, instead of data being saved to system memory first. Added progress bar as well.

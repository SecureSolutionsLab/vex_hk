use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::Parser;
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use vex_hk::{config::Config, state::ScraperState};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
    #[arg(short, long)]
    regenerate_config: bool,

    #[arg(short, long)]
    github_sync_manual: bool,

    #[arg(long)]
    osv_download_manual: bool,
    #[arg(long)]
    osv_update_manual: bool,
}

fn read_config(path: &Path) -> anyhow::Result<Config> {
    let mut reader = io::BufReader::new(fs::File::open(path)?);
    let result: Result<Config, serde_json::Error> = serde_json::from_reader(&mut reader);
    result.map_err(|err| err.into())
}

fn read_state(config: &Config) -> anyhow::Result<ScraperState> {
    let file_open_result = fs::File::open(&config.state_file_location);
    if let Err(ref err) = file_open_result
        && err.kind() == io::ErrorKind::NotFound
    {
        log::warn!("State file not found. Setting state to initial values.");
        return Ok(ScraperState::default());
    }

    let mut reader = io::BufReader::new(file_open_result?);
    let result: Result<ScraperState, serde_json::Error> = serde_json::from_reader(&mut reader);
    result.map_err(|err| err.into())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();

    // indicatif rust log progress bar initialization
    let level = logger.filter();
    let pg_bars = MultiProgress::new();
    LogWrapper::new(pg_bars.clone(), logger).try_init().unwrap();
    log::set_max_level(level);

    let args = Cli::parse();
    if args.regenerate_config {
        println!("Generating default config at {:?}.", args.config);
        let default_config = Config::default();

        let mut writer = io::BufWriter::new(fs::File::create(args.config)?);
        serde_json::to_writer_pretty(&mut writer, &default_config)?;
        writer.flush()?;

        println!("Config generated successfully. Edit it before running future operations.");
        return Ok(());
    }

    let config = read_config(&args.config)?;
    let mut state = read_state(&config)?;
    let db_conn = vex_hk::get_db_connection().await.unwrap();
    let client = reqwest::Client::new();

    if args.github_sync_manual {
        log::info!("Starting GitHub OSV manual sync");
        return vex_hk::scrape_mod::github::repository::sync(
            &config, &client, &db_conn, &pg_bars, &mut state,
        )
        .await;
    }

    if args.osv_download_manual {
        log::info!("Downloading osv and recreating the table");
        return vex_hk::scrape_mod::osv::manual_download_and_save_state(
            &config, &client, &db_conn, &pg_bars, &mut state,
        )
        .await;
    }
    if args.osv_update_manual {
        log::info!("Attempting to manually update OSV");
        return vex_hk::scrape_mod::osv::manual_update_and_save_state(
            &config, &client, &db_conn, &pg_bars, &mut state,
        )
        .await;
    }

    Ok(())
}

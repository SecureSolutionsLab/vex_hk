use log::{error, info, warn};
use vex_hk::{osv_scraper};


#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init(); // Initialize the logger
    info!("This is an info log.");
    warn!("This is a warning.");
    error!("This is an error.");
    // _exploit_vulnerability_hunter().await;
    // _exploitdb_scraper().await;
    osv_scraper().await;
}

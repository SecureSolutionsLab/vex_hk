pub mod consts;
pub mod structs;

#[cfg(feature = "alienvault")]
pub mod alienvault_scraper;
#[cfg(feature = "exploitdb")]
pub mod exploitdb_scraper;
#[cfg(feature = "nvd")]
pub mod nvd_scraper;
#[cfg(feature = "osv")]
pub mod osv_scraper;

pub mod github;

// ?
fn _private_hello() {
    println!("hello world")
}

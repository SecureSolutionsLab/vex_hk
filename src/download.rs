use std::{fs, path::Path, time::Instant};

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

#[derive(thiserror::Error, Debug)]
pub enum DownloadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Reqwest HTTP Error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// Download and stream to a file without storing the contents in memory (best for very big files).
///
/// Creates a folder for the download file if it doesn't already exist.
///
/// Uses a tokio BufWriter in order to not perform much spawn_blocking.
pub async fn download_and_save_to_file_in_chunks(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), DownloadError> {
    let start_instant = Instant::now();
    log::info!("Creating download file at {:?}", file_path);

    let parent = file_path.parent().unwrap();
    if !fs::exists(parent)? {
        fs::create_dir(parent)?;
    }

    let mut file = tokio::io::BufWriter::new(tokio::fs::File::create(file_path).await?);

    log::info!("Performing request to {}...", url);
    let response = client.get(url).send().await?;
    let bar = if let Some(content_len) = response.content_length() {
        log::info!(
            "Request successful. Starting download. ({})",
            human_bytes::human_bytes(content_len as f64)
        );
        pg_bars.add(indicatif::ProgressBar::new(content_len))
    } else {
        log::warn!("Request successful, however content length could not be retrieved. Attempting download.");
        pg_bars.add(indicatif::ProgressBar::no_length())
    };

    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        file.write_all(&chunk).await?;

        bar.inc(chunk.len() as u64);
    }

    bar.finish();
    pg_bars.remove(&bar);

    file.flush().await?;

    log::info!(
        "Download complete. Time: {:?}\nFile saved locally at {:?}",
        start_instant.elapsed(),
        file_path
    );
    Ok(())
}

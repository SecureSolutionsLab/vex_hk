// use std::error::Error;
//
// fn alienvault_crawler() {
//     // let api_key = String::from("26abd167ab18baa5cc8496b68dd03354017a9f31a7d9466420a1454c138d821f");
//     // let client = Client::new();
//     //
//     // // Calculate the timestamp for one hour ago
//     // // let one_hour_ago = Utc::now() - Duration::hours(24);
//     // // let timestamp = one_hour_ago.to_rfc3339(); // ISO 8601 format
//     // // let initial_url = format!(
//     // //     "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={}&limit=50",
//     // //     timestamp
//     // // );
//     //
//     // // JSON payload to request only the `pulse_info` section
//     // // let payload = json!({
//     // //     "sections": ["pulse_info"]
//     // // });
//     //
//     // // Initial request to determine total pages
//     // // let initial_url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1&limit=2";
//     // let initial_url = "https://otx.alienvault.com//api/v1/indicators/cve/CVE-2002-0062/general";
//     // let initial_response = client
//     //     .get(initial_url)
//     //     .header("X-OTX-API-KEY", &api_key)
//     //     // .json(&payload) // Attach the JSON payload
//     //     .send()
//     //     .await?
//     //     .text()
//     //     .await?;
//     // println!("{}", initial_response);
//     // let initial_json: Value = serde_json::from_str(&initial_response)?;
//     // let total_entries = initial_json["pulse_info"]["count"].clone().as_f64().unwrap();
//     let total_entries = get_pulses(&String::from("CVE-2002-0062")).await;
//     println!("Pulse info count: {}", total_entries);
//     // let total_pages = (total_entries + 4) / 50;
//     //
//     // println!("Total pulses count: {}, Total pages: {}", total_entries, total_pages);
//     //
//     //     let pulses = Arc::new(Mutex::new(Vec::<Entry>::new()));
//     //     let start = Instant::now();
//     //
//     //     // Spawn async tasks for each page
//     //     let mut tasks = Vec::new();
//     //     for page in 1..=total_pages {
//     //         let client = client.clone();
//     //         let api_key = api_key.clone();
//     //         let pulses = Arc::clone(&pulses);
//     //
//     //         let task = tokio::spawn(async move {
//     //             if let Ok(entries) = fetch_and_parse_page(&client, &api_key, page).await {
//     //                 let mut pulses_guard = pulses.lock().unwrap(); // Use asynchronous lock here
//     //                 pulses_guard.extend(entries);
//     //                 println!("Processed page {}", page);
//     //             }
//     //         });
//     //
//     //         tasks.push(task);
//     //     }
//     //
//     //     for task in tasks {
//     //         task.await.unwrap();
//     //     }
//     //
//     //     let end = Instant::now();
//     //     println!("Total Pulses: {}, Time: {:.2?}", pulses.lock().unwrap().len(), end - start);
//     Ok(())
// }
//
// // Function to read all files in the directory and deserialize them into `Advisory` structs
// pub async fn read_advisories_from_dir(
//     dir_path: &str,
// ) -> Result<Vec<Advisory>, Box<dyn Error + Send + Sync>> {
//     let mut advisories = Vec::new();
//
//     // Collect all `.json` file paths from the directory
//     let mut paths = Vec::new();
//     let mut entries = read_dir(dir_path).await?;
//
//     while let Some(entry) = entries.next_entry().await? {
//         let path = entry.path();
//
//         if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json") {
//             paths.push(path);
//         } else {
//             println!("Ignoring: {}", path.display());
//         }
//     }
//     println!("Reading advisories from {}", paths.len());
//
//     // Iterate through each file and read it into an Advisory struct
//     for (index, path) in paths.iter().enumerate() {
//         let contents = read_to_string(&path).await?;
//
//         // Deserialize the contents into an Advisory struct
//         match serde_json::from_str::<Advisory>(&contents) {
//             Ok(advisory) => advisories.push(advisory),
//             Err(e) => eprintln!("Error deserializing file {:?}: {}", path, e),
//         }
//         if advisories.len() == 10000 || index == paths.len() - 1 {
//             // println!("finished");
//             let db = get_db_connection().await?;
//             insert_parallel(&db, "osv", "osv_data", &advisories).await?;
//             advisories.clear();
//         }
//     }
//
//     Ok(advisories)
// }

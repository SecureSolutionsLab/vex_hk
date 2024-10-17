use std::time::Instant;

use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, query, Pool, Postgres, Row};

use crate::crawl_mod::structs::{CPEMatch, FilteredCVE};
use crate::utils::tools::get_db;

pub async fn insert_parallel_db(cves: &Vec<FilteredCVE>, configuration: Vec<(String, Vec<Vec<CPEMatch>>)>) {
    let instant = Instant::now();

    let db = get_db_connection().await;
    let mut submit_cve = vec![];
    let mut submit_cveid = vec![];
    let mut submit_configuration = vec![];
    for cve in cves {
        submit_cve.push(json!(cve))
    }
    for (cveid, configuration) in configuration {
        submit_cveid.push(cveid);
        submit_configuration.push(json!(configuration));
    }

    let result = query!(
        "insert into cves(cve) select unnest($1::jsonb[])",
        &submit_cve
    )
    .execute(&db)
    .await
    .unwrap();
    let result = query!(
        "insert into configurations(cveid, configuration) select vec.cve_id, vec.config from unnest($1::text[], $2::jsonb[]) AS vec(cve_id, config)", &submit_cveid,
        &submit_configuration)
        .execute(&db)
        .await
        .unwrap();
    // println!("database insertion {:.2?}, size {} {:?}", instant.elapsed(), cves.len(), result);
}

pub async fn remove_to_update(cves: &Vec<FilteredCVE>) {
    let instant = Instant::now();

    let db = get_db_connection().await;
    let mut id_vec = vec![];
    for cve in cves {
        id_vec.push(cve.id.clone());
    }
    let result = query!(
        "delete from cves where cve->>'id' in (select unnest($1::Text[]))",
        &id_vec
    )
    .execute(&db)
    .await
    .unwrap();
    println!(
        "database deletion {:.2?}, size {} {:?}",
        instant.elapsed(),
        cves.len(),
        result
    );
}

pub async fn _insert_db_sequential<T: serde::Serialize>(cve: Vec<T>) {
    let instant = Instant::now();
    let db = get_db_connection().await;
    for value in &cve {
        let json_cve = json!(value);
        let _query = query("insert into cves(cve) VALUES ($1)")
            .bind(&json_cve)
            .execute(&db)
            .await
            .unwrap();
    }
    println!(
        "database insertion {:.2?}, size {}",
        instant.elapsed(),
        cve.len()
    );
}

/// Verify repeated entries (CVES are unique)
pub async fn verify_database() -> usize {
    let instant = Instant::now();
    let db = get_db_connection().await;
    // let query = query("SELECT * FROM cves WHERE cve IN (SELECT cve FROM cves GROUP BY cve HAVING COUNT(*) > 1);").fetch_all(&db).await.unwrap();
    let query = query(
        "SELECT cve->'id' AS cve_id, COUNT(*) FROM cves GROUP BY cve->'id' HAVING COUNT(*) > 1;",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    println!(
        "database verification {:.2?}, size {}",
        instant.elapsed(),
        query.len()
    );
    query.len()
}

/// Verify repeated cves within the database (slow operation)
pub async fn _verify_cve_db(id: &str) -> bool {
    let query_db_size = query("select count(*) from cves where cve->>'id' = $1;")
        .bind(id)
        .fetch_all(&get_db_connection().await)
        .await
        .unwrap();
    let count: i64 = query_db_size.get(0).unwrap().get("count");
    if count == 1 {
        return true;
    } else if count > 1 {
        println!("too many entries for {}", id);
        return true;
    }
    false
}

pub async fn count_cve_db() -> i64 {
    let query_db = query("SELECT count(*) FROM CVES;")
        .fetch_all(&get_db_connection().await)
        .await
        .unwrap();
    let count_db = query_db.len() as i64;
    if count_db > 1 {
        panic!("something went wrong with query: count_cve_db");
    }
    let count: i64 = query_db.get(0).unwrap().get("count");
    count
}

pub async fn get_db_connection() -> Pool<Postgres> {
    let connection = PgPoolOptions::new().connect(&*get_db()).await;

    connection.unwrap_or_else(|error| {
        println!("error in db connection {}", error);
        panic!("db_connection")
    })
}

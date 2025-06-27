use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::scrape_mod::structs::HasId;

#[derive(Debug, FromRow)]
pub struct EntryStatus {
    pub id: String,
    pub status: String,
}

impl HasId for &EntryStatus {
    fn get_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EntryInput {
    pub(crate) id: String,
    pub(crate) modified: String,
}

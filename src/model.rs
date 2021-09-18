use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Config {
    pub ews_url: String,
    pub username: String,
    pub domain: String,
    pub local_hostname: String,
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FolderId {
    pub id: String,
    pub change_key: String,
}
impl FolderId {
    pub fn new(
        id: String,
        change_key: String,
    ) -> Self {
        Self {
            id,
            change_key,
        }
    }
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Calendar {
    pub folder_id: FolderId,
    pub display_name: String,
}
impl Calendar {
    pub fn new(
        folder_id: FolderId,
        display_name: String,
    ) -> Self {
        Self {
            folder_id,
            display_name,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NewEvent {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub title: String,
    pub location: Option<String>,
}
impl NewEvent {
    pub fn new(
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        title: String,
        location: Option<String>,
    ) -> Self {
        Self {
            start_time,
            end_time,
            title,
            location,
        }
    }
}

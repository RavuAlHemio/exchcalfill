use chrono::{DateTime, Utc};


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
    pub free_busy_status: FreeBusyStatus,
}
impl NewEvent {
    pub fn new(
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        title: String,
        location: Option<String>,
        free_busy_status: Option<FreeBusyStatus>,
    ) -> Self {
        Self {
            start_time,
            end_time,
            title,
            location,
            free_busy_status: free_busy_status.unwrap_or_default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FreeBusyStatus {
    Free,
    Tentative,
    #[default] Busy,
    OutOfOffice,
    WorkingElsewhere,
    NoData,
}
impl FreeBusyStatus {
    pub fn as_exchange_str(&self) -> &'static str {
        match self {
            Self::Free => "Free",
            Self::Tentative => "Tentative",
            Self::Busy => "Busy",
            Self::OutOfOffice => "OOF",
            Self::WorkingElsewhere => "WorkingElsewhere",
            Self::NoData => "NoData",
        }
    }
}

//! This file defines the `LoginData` type
//!
//! `LoginData` is a set of data with the encrypted password and its relevant data

use chrono::prelude::*;

#[derive(Debug, Clone)]
pub struct LoginData {
    pub id: usize,
    pub name: String,
    pub username: String,
    pub date_modified: String,
    pub password: String,
}

impl LoginData {
    pub fn new(name: String, username: String, password: String) -> Self {
        let current_time: DateTime<Local> = DateTime::from(Utc::now());
        let iso8601 = current_time.to_rfc2822();
        Self {
            id: 0,
            name,
            username,
            date_modified: iso8601,
            password,
        }
    }
}
